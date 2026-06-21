package com.jesusf.paydude.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jesusf.paydude.config.properties.IdempotencyProperties;
import com.jesusf.paydude.dto.idempotent.IdempotentRequest;
import com.jesusf.paydude.entity.IdempotencyKey;
import com.jesusf.paydude.enums.IdempotencyKeyStatus;
import com.jesusf.paydude.exception.BusinessException;
import com.jesusf.paydude.metrics.BusinessMetrics;
import com.jesusf.paydude.metrics.BusinessMetrics.IdempotencyConflictReason;
import com.jesusf.paydude.repository.IdempotencyKeyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

/**
 * Default {@link IdempotencyKeyService} implementation.
 *
 * <p>{@code reserveKey} looks the row up first under a {@code PESSIMISTIC_WRITE} lock, then inserts
 * only when absent. The earlier insert-first variant is unsafe on Postgres: a {@code UNIQUE
 * (key_value, user_id)} violation aborts the transaction, so the recovery query that followed it in
 * the catch block failed (Hibernate flushed the failed null-id entity → {@code AssertionFailure}).
 * Looking up first keeps every replay/conflict/reclaim decision exception-free, and the row lock
 * serializes concurrent reservations for the same key so the chain can never fork. The one
 * remaining {@code DataIntegrityViolationException} — two first-time requests racing on a brand-new
 * key — is reported as in-progress without a follow-up query. The reservation runs in
 * {@code REQUIRES_NEW} so the key row commits independently of the money-moving transaction it
 * guards.
 *
 * <p><b>Known trade-off — a crash can strand a key in {@code PENDING}.</b> If the JVM dies between
 * the reservation commit and the operation's COMPLETED/FAILED resolution (the
 * {@code AFTER_ROLLBACK} listener never fires on a crash), retries of that key answer
 * "operation in progress" until the TTL ({@code application.idempotency.key-ttl}) reclaims the
 * row. This is deliberate: a stale-{@code PENDING} heuristic that reclaims "old enough" rows
 * cannot distinguish a crashed attempt from one still executing under lock contention, and
 * guessing wrong re-executes a money movement — the exact failure idempotency exists to prevent.
 * The client-side escape hatch is simply retrying with a fresh key.
 */
@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
class IdempotencyKeyServiceImpl implements IdempotencyKeyService {

  private final IdempotencyKeyRepository idempotencyKeyRepository;
  @Qualifier("canonicalJsonMapper")
  private final ObjectMapper canonicalJsonMapper;
  // TTL for freshly reserved keys (expiresAt = now + keyTtl at insert). ExpiredDataCleanupJob
  // deletes rows once this window elapses, reclaiming them and restoring true TTL semantics on reuse.
  private final IdempotencyProperties idempotencyProperties;
  private final BusinessMetrics metrics;

  @Override
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public ReservationOutcome reserveKey(
      String idempotencyKey,
      Long userId,
      String operation,
      IdempotentRequest request
  ) {
    String requestHash = computeRequestHash(operation, request);

    // ========================================
    // LOOK UP FIRST (under a row lock)
    // ========================================
    // A row already present is the common path (replay, conflict, or an expired slot to reclaim).
    // Resolving it with a locked SELECT — rather than insert-first — keeps it exception-free; the
    // PESSIMISTIC_WRITE lock serializes concurrent reservations for the SAME key so a replay or a
    // reclaim is decided by exactly one caller and the row never forks.
    Optional<IdempotencyKey> existing =
        idempotencyKeyRepository.findByKeyValueAndUserIdForUpdate(idempotencyKey, userId);
    if (existing.isPresent()) {
      return handleExisting(existing.get(), idempotencyKey, requestHash);
    }

    // ========================================
    // CLAIM THE SLOT
    // ========================================
    // No row yet — insert a PENDING reservation. Only a genuine race (two first-time requests for
    // the same brand-new key, neither having seen the other's row) can still hit the UNIQUE
    // violation. The loser must NOT query here: the failed INSERT has aborted this transaction, so
    // it reports in-progress directly and rolls back. The winner keeps the PENDING reservation.
    try {
      IdempotencyKey newKey = IdempotencyKey.builder()
          .keyValue(idempotencyKey)
          .userId(userId)
          .requestHash(requestHash)
          .expiresAt(Instant.now().plus(idempotencyProperties.keyTtl()))
          .build();

      return new ReservationOutcome.Fresh(idempotencyKeyRepository.save(newKey));
    } catch (DataIntegrityViolationException e) {
      metrics.recordIdempotencyConflict(IdempotencyConflictReason.STILL_PENDING);
      throw new BusinessException(
          "Operation already in progress for this idempotency key. Please wait."
      );
    }
  }

  /**
   * Decides the outcome for a {@code (key, user)} that already has a row, held under the
   * {@code PESSIMISTIC_WRITE} lock acquired by {@code findByKeyValueAndUserIdForUpdate}.
   *
   * <p>Order matters. An <b>expired</b> row is checked first and reclaimed in place as a fresh
   * reservation: once past its TTL the key is logically gone (the cleanup job would delete it), so
   * it is reusable with ANY body — which is exactly why the expiry check precedes the hash
   * comparison, so an expired row can never become a "same key, different body" oracle. The lock
   * guarantees a single reclaimer; a concurrent caller blocks, then re-reads the row already reset
   * to a non-expired {@code PENDING} and falls through to the in-progress branch below.
   */
  private ReservationOutcome handleExisting(
      IdempotencyKey existingKey, String idempotencyKey, String requestHash) {

    if (existingKey.getExpiresAt().isBefore(Instant.now())) {
      existingKey.setRequestHash(requestHash);
      existingKey.setStatus(IdempotencyKeyStatus.PENDING);
      existingKey.setResponseBody(null);
      existingKey.setExpiresAt(Instant.now().plus(idempotencyProperties.keyTtl()));
      log.info("Idempotency key {} was past its TTL — reclaimed as a fresh reservation", idempotencyKey);
      return new ReservationOutcome.Fresh(idempotencyKeyRepository.save(existingKey));
    }

    // Hash mismatch on a still-live key: same key, different operation/body — programmer error or
    // replay attack.
    if (!existingKey.getRequestHash().equals(requestHash)) {
      metrics.recordIdempotencyConflict(IdempotencyConflictReason.HASH_MISMATCH);
      throw new BusinessException("Idempotency key already used with different request parameters");
    }

    return switch (existingKey.getStatus()) {
      case COMPLETED -> {
        // Defensive: the original attempt completed but its response failed to serialize at the
        // time, so we have no bytes to replay. Reject here so the Replay outcome can guarantee a
        // non-null body to consumers — the contract becomes "if you got a Replay, you can use it".
        String body = existingKey.getResponseBody();
        if (body == null) {
          throw new BusinessException(
              "Original response no longer available for this idempotency key. Use a new key to retry."
          );
        }
        log.info("Idempotency hit (COMPLETED) for key: {} - returning cached response", idempotencyKey);
        metrics.recordIdempotencyReplay();
        yield new ReservationOutcome.Replay(existingKey.getId(), body);
      }
      case FAILED -> {
        log.info("Idempotency hit (FAILED) for key: {} - previous attempt failed", idempotencyKey);
        metrics.recordIdempotencyConflict(IdempotencyConflictReason.PREVIOUS_FAILED);
        throw new BusinessException(
            "Previous operation attempt with this idempotency key failed. Use a new key to retry."
        );
      }
      case PENDING -> {
        metrics.recordIdempotencyConflict(IdempotencyConflictReason.STILL_PENDING);
        throw new BusinessException(
            "Operation already in progress for this idempotency key. Please wait."
        );
      }
    };
  }

  /**
   * Caches the serialized response on the key and marks it COMPLETED.
   *
   * <p>Intentionally uses the default propagation ({@code REQUIRED}) so this call joins the
   * caller's transfer transaction. If the transfer rolls back later, this update rolls back too —
   * the key is then re-marked as {@code FAILED} by {@code IdempotencyCleanupListener}, which runs
   * in its own {@code REQUIRES_NEW} transaction (the listener observes the rollback event and
   * persists outside the doomed transaction).
   */
  @Override
  @Transactional(rollbackFor = Exception.class)
  public void complete(IdempotencyKey key, String responseBody) {
    key.setStatus(IdempotencyKeyStatus.COMPLETED);
    key.setResponseBody(responseBody);
    idempotencyKeyRepository.save(key);
  }

  @Override
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void markAsFailed(Long keyId) {
    try {
      idempotencyKeyRepository.findById(keyId)
          .ifPresentOrElse(
              key -> {
                key.setStatus(IdempotencyKeyStatus.FAILED);
                idempotencyKeyRepository.save(key);
                log.info("Idempotency key {} marked as FAILED after transfer rollback", keyId);
              },
              () -> log.warn("Idempotency key {} not found when trying to mark as FAILED", keyId)
          );
    } catch (Exception e) {
      log.error("Failed to mark idempotency key {} as FAILED — will expire naturally via expires_at", keyId, e);
    }
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public int deleteExpired(Instant cutoff) {
    return idempotencyKeyRepository.deleteByExpiresAtBefore(cutoff);
  }

  /**
   * Computes the deterministic fingerprint of an idempotent operation.
   *
   * <p>The result is stored in the {@code request_hash} column. On a retry, we recompute the hash
   * from the operation scope plus the new request body and compare it against the stored one. If
   * they differ, the caller is trying to reuse the same idempotency key for a <i>different</i>
   * operation — a programmer error or replay attack — and we reject it with {@link BusinessException}.
   *
   * <p>The operation scope is deliberately hashed together with the body. Deposit and withdraw
   * both use {@code AccountOperationRequest}; without a scope, the same key and amount could make
   * a withdraw replay a previous deposit response instead of being rejected.
   *
   * <p>For that comparison to be reliable the hashing pipeline must satisfy three properties:
   *
   * <ol>
   *   <li><b>Injection-safe.</b> Two semantically different inputs must never collide on the same
   *       digest just because of a shared character. The previous {@code String.format("%s|%s|%s|%s", ...)}
   *       was the textbook way to introduce collisions: a {@code description} containing {@code "|"}
   *       could produce the exact same string as a different {@code currency} field. JSON
   *       serialization escapes special characters, so the structure of the document is
   *       unambiguous regardless of content.</li>
   *
   *   <li><b>Canonical.</b> The same logical input must always produce the exact same bytes,
   *       even if the JVM, the DTO definition, or the JSON library reorders fields. The
   *       canonical mapper is configured with {@code SORT_PROPERTIES_ALPHABETICALLY} (see
   *       {@code IdempotencyConfig}) so the field order is fixed regardless of the source.</li>
   *
   *   <li><b>Type-stable.</b> {@link java.math.BigDecimal} preserves trailing zeros in its string
   *       form, so {@code "100"}, {@code "100.0"} and {@code "100.00"} would otherwise produce
   *       three different representations for the same monetary value. The canonical mapper
   *       installs a custom {@code BigDecimal} serializer that strips trailing zeros, so retries
   *       that vary in formatting (frontend rounding, JSON parsing flavors) still hash identically.</li>
   * </ol>
   *
   * <p>The output is the SHA-256 digest of the canonical JSON encoded as a lowercase hex string.
   * SHA-256 is overkill cryptographically for this use case (we don't need collision resistance
   * against an adversary, only structural uniqueness), but it's the industry default, fits in the
   * existing {@code request_hash VARCHAR(64)} column, and is faster than any second-guessing.
   */
  private String computeRequestHash(String operation, IdempotentRequest request) {
    try {
      ScopedIdempotencyRequest scopedRequest = new ScopedIdempotencyRequest(
          requireOperation(operation),
          request
      );
      // writeValueAsBytes returns UTF-8 by default, which is what SHA-256 expects.
      byte[] canonicalJson = canonicalJsonMapper.writeValueAsBytes(scopedRequest);
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonicalJson);

      // HexFormat (Java 17+) replaces the manual byte-to-hex loop. It is locale-independent
      // and produces lowercase hex by default — exactly what we want for a stable database key.
      return HexFormat.of().formatHex(digest);
    } catch (JsonProcessingException e) {
      // Serialization should never fail for a validated DTO. If it ever does, we fail loud
      // rather than store a half-formed hash that future retries would never match.
      throw new IllegalStateException("Failed to serialize IdempotentRequest for hashing", e);
    } catch (NoSuchAlgorithmException e) {
      // SHA-256 is mandated by every JRE since Java 1.4.2; this branch is theoretical.
      throw new IllegalStateException("SHA-256 algorithm not available", e);
    }
  }

  private static String requireOperation(String operation) {
    if (operation == null || operation.isBlank()) {
      throw new IllegalArgumentException("Idempotency operation scope must not be blank");
    }
    return operation;
  }

  /**
   * Hash envelope used only inside the idempotency layer.
   *
   * <p>Keeping the operation outside the DTOs avoids leaking endpoint-specific infrastructure
   * fields into public request bodies while still making the fingerprint unambiguous.
   */
  private record ScopedIdempotencyRequest(String operation, IdempotentRequest request) {
    private ScopedIdempotencyRequest {
      Objects.requireNonNull(request, "Idempotent request must not be null");
    }
  }
}
