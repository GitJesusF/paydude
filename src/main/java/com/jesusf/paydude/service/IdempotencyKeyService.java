package com.jesusf.paydude.service;

import com.jesusf.paydude.dto.idempotent.IdempotentRequest;
import com.jesusf.paydude.entity.IdempotencyKey;
import com.jesusf.paydude.exception.BusinessException;

import java.time.Instant;
import java.util.Objects;

/**
 * Manages the lifecycle of idempotency-key reservations: reserve a slot, mark it completed with
 * the cached response, or mark it failed.
 *
 * <p>The implementation runs the reservation in {@code REQUIRES_NEW} so the key row persists
 * independently of the money-moving transaction it guards — which is what lets a rolled-back
 * operation still leave a {@code FAILED} key behind for the cleanup listener.
 */
public interface IdempotencyKeyService {

  /**
   * Reserves an idempotency slot for {@code (key, userId)} and fingerprints the operation plus
   * request body so future retries can be compared against the original.
   *
   * <p>The operation scope is part of the fingerprint on purpose. Once multiple endpoints share
   * the same idempotency table, the same key must not replay a different money movement just
   * because its request body happens to look identical.
   *
   * <p>Returns one of two outcomes — modeled as a {@link ReservationOutcome} sealed type rather
   * than a raw {@link IdempotencyKey} so callers handle exactly the cases that exist on the happy
   * path. All other situations (hash mismatch, previous attempt FAILED or still PENDING, COMPLETED
   * row with a missing body) raise a domain exception inside this method and never reach the
   * caller as a value.
   */
  ReservationOutcome reserveKey(String key, Long userId, String operation, IdempotentRequest request);

  /**
   * Marks a reserved key {@code COMPLETED} and stores the serialized response body that future
   * retries will replay.
   *
   * @param key          the {@code Fresh} key returned by {@link #reserveKey}
   * @param responseBody the serialized operation response to cache
   */
  void complete(IdempotencyKey key, String responseBody);

  /**
   * Marks a reserved key {@code FAILED} so a retry can proceed with a fresh key. Invoked by
   * {@code IdempotencyCleanupListener} when the money-moving transaction rolls back.
   *
   * @param keyId the id of the key to fail
   */
  void markAsFailed(Long keyId);

  /**
   * Bulk-deletes every reservation whose TTL has elapsed ({@code expiresAt < cutoff}). Invoked by
   * the scheduled cleanup job. Reclaims rows that the reservation flow never enforced on reuse —
   * an expired key is past its retry window — so this both bounds table growth and gives the key
   * true TTL semantics (once purged, the same key value can be reserved fresh again).
   *
   * @param cutoff rows with {@code expiresAt} strictly before this instant are removed
   * @return the number of rows deleted
   */
  int deleteExpired(Instant cutoff);

  /**
   * Result of {@link #reserveKey}. Exhaustive sealed hierarchy with two cases:
   *
   * <ul>
   *   <li>{@link Fresh} — the slot was inserted for the first time. The caller owns the key and
   *       must execute the operation, then call {@link #complete} with the serialized response.</li>
   *   <li>{@link Replay} — an existing COMPLETED row with a matching hash was found. The caller
   *       returns the cached body without re-executing the operation.</li>
   * </ul>
   *
   * <p>A {@code switch} over this type is exhaustive at compile time, so the consumer side has no
   * dead "should never happen" branch for FAILED/PENDING/hash-mismatch — those are translated to
   * {@link BusinessException} inside {@code reserveKey} and never surface as a value.
   */
  sealed interface ReservationOutcome {

    /** Fresh PENDING row inserted for this (key, user). Caller executes the operation. */
    record Fresh(IdempotencyKey key) implements ReservationOutcome {
      public Fresh {
        Objects.requireNonNull(key, "Fresh outcome requires an IdempotencyKey");
      }
    }

    /**
     * Existing key with matching hash, status COMPLETED, body present. Caller returns the cached
     * body without re-executing the operation. The key id is exposed for error logging on
     * deserialization failures; the entity itself is hidden so the caller cannot mutate it.
     */
    record Replay(Long keyId, String cachedResponseBody) implements ReservationOutcome {
      public Replay {
        Objects.requireNonNull(keyId, "Replay outcome requires a key id");
        Objects.requireNonNull(
            cachedResponseBody,
            "Replay outcome requires a non-null cached body — a COMPLETED key with no body must be rejected upstream"
        );
      }
    }
  }
}