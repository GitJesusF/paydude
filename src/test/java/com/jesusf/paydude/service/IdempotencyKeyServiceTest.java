package com.jesusf.paydude.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jesusf.paydude.config.IdempotencyConfig;
import com.jesusf.paydude.config.properties.IdempotencyProperties;
import com.jesusf.paydude.dto.idempotent.AccountOperationRequest;
import com.jesusf.paydude.dto.idempotent.TransferRequest;
import com.jesusf.paydude.entity.IdempotencyKey;
import com.jesusf.paydude.enums.IdempotencyKeyStatus;
import com.jesusf.paydude.exception.BusinessException;
import com.jesusf.paydude.metrics.BusinessMetrics;
import com.jesusf.paydude.repository.IdempotencyKeyRepository;
import com.jesusf.paydude.service.IdempotencyKeyService.ReservationOutcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IdempotencyKeyServiceImpl}.
 *
 * <p>The service implements lookup-under-lock idempotency and is the single source of truth for
 * whether a request is a fresh attempt, a legitimate retry, an expired-key reclaim, or a replay
 * with a mutated body. Four contracts are pinned here: (1) the canonical hash is stable across
 * BigDecimal scale variations and oblivious to fields excluded by the canonical mix-in
 * (description); (2) the same live key reused with a different body is rejected with a domain
 * exception, never silently accepted; (3) the same live key reused with the same body short-circuits
 * to the cached row without re-inserting; (4) expired rows are reclaimed before hash comparison.
 * The integration test exercises the same flow against a real Postgres unique constraint.
 *
 * <p>The {@code canonicalJsonMapper} is the REAL production bean
 * ({@code IdempotencyConfig.canonicalJsonMapper()}), never a mock: changes to field ordering, the
 * BigDecimal serializer or the per-DTO mix-ins propagate here automatically. A mocked ObjectMapper
 * would green-light behaviour production does not have.
 */
@ExtendWith(MockitoExtension.class)
class IdempotencyKeyServiceTest {

  @Mock private IdempotencyKeyRepository idempotencyKeyRepository;
  @Mock private BusinessMetrics metrics;

  private IdempotencyKeyServiceImpl service;

  // Operation scope reused across the TransferRequest-based tests. The actual value only needs to
  // be consistent within each test (so a hash diff is attributable to the body, not the scope) —
  // the dedicated scope-sensitivity test uses two distinct scopes on purpose.
  private static final String TRANSFER_OPERATION = "transactions.transfer";

  @BeforeEach
  void setUp() {
    ObjectMapper canonicalJsonMapper = new IdempotencyConfig().canonicalJsonMapper();
    // The TTL value is irrelevant to these tests; building the record literal beats mocking it.
    IdempotencyProperties properties = new IdempotencyProperties(Duration.ofHours(24));
    service = new IdempotencyKeyServiceImpl(idempotencyKeyRepository, canonicalJsonMapper, properties, metrics);
  }

  @Nested
  @DisplayName("deleteExpired — bulk-deletes reservations past their TTL")
  class DeleteExpired {

    @Test
    @DisplayName("delegates to the repository with the given cutoff and returns the deleted count")
    void delegatesToRepository() {
      Instant cutoff = Instant.parse("2026-01-01T00:00:00Z");
      when(idempotencyKeyRepository.deleteByExpiresAtBefore(cutoff)).thenReturn(7);

      int deleted = service.deleteExpired(cutoff);

      assertEquals(7, deleted, "the count must be propagated from the repository verbatim");
      verify(idempotencyKeyRepository).deleteByExpiresAtBefore(cutoff);
    }
  }

  @Nested
  @DisplayName("Canonical hashing — fingerprint stability and field selectivity")
  class CanonicalHashing {

    @Test
    @DisplayName("BigDecimal('100') and BigDecimal('100.00') hash to the same canonical value")
    void shouldProduceIdenticalHashForEquivalentBigDecimals() {
      // A frontend that re-stringifies the amount between the original attempt and the retry
      // ("100" vs "100.00") must not be rejected as "same key, different request" — the custom
      // BigDecimal serializer normalizes via stripTrailingZeros().toPlainString().
      TransferRequest withInteger = new TransferRequest(
          "ACC-001", "ACC-002", new BigDecimal("100"), "USD", "rent"
      );
      TransferRequest withTrailingZeros = new TransferRequest(
          "ACC-001", "ACC-002", new BigDecimal("100.00"), "USD", "rent"
      );

      when(idempotencyKeyRepository.save(any(IdempotencyKey.class)))
          .thenAnswer(inv -> inv.getArgument(0));

      service.reserveKey("key-A", 1L, TRANSFER_OPERATION, withInteger);
      service.reserveKey("key-B", 1L, TRANSFER_OPERATION, withTrailingZeros);

      ArgumentCaptor<IdempotencyKey> keyCaptor = ArgumentCaptor.forClass(IdempotencyKey.class);
      verify(idempotencyKeyRepository, times(2)).save(keyCaptor.capture());

      List<IdempotencyKey> savedKeys = keyCaptor.getAllValues();
      assertEquals(savedKeys.get(0).getRequestHash(), savedKeys.get(1).getRequestHash(),
          "BigDecimal('100') and BigDecimal('100.00') must hash to the same canonical value");
    }

    @Test
    @DisplayName("Description is excluded from the hash by the canonical mix-in")
    void shouldIgnoreDescriptionDifferencesInHash() {
      // Description is human metadata; a UI that normalizes the memo between attempts must not
      // trip the different-request rejection. A failure here usually means the mix-in fell out
      // of the canonicalJsonMapper registration in IdempotencyConfig.
      TransferRequest withMemoA = new TransferRequest(
          "ACC-001", "ACC-002", new BigDecimal("100.00"), "USD", "Payment for rent"
      );
      TransferRequest withMemoB = new TransferRequest(
          "ACC-001", "ACC-002", new BigDecimal("100.00"), "USD", "rent — march"
      );

      when(idempotencyKeyRepository.save(any(IdempotencyKey.class)))
          .thenAnswer(inv -> inv.getArgument(0));

      service.reserveKey("key-A", 1L, TRANSFER_OPERATION, withMemoA);
      service.reserveKey("key-B", 1L, TRANSFER_OPERATION, withMemoB);

      ArgumentCaptor<IdempotencyKey> keyCaptor = ArgumentCaptor.forClass(IdempotencyKey.class);
      verify(idempotencyKeyRepository, times(2)).save(keyCaptor.capture());

      List<IdempotencyKey> savedKeys = keyCaptor.getAllValues();
      assertEquals(savedKeys.get(0).getRequestHash(), savedKeys.get(1).getRequestHash(),
          "Description differences must not change the canonical hash");
    }

    @Test
    @DisplayName("Semantically different requests produce different hashes")
    void shouldProduceDifferentHashesForDifferentRequests() {
      // Inverse sanity check: without it, the stability tests would pass vacuously if the
      // algorithm collapsed every input to a constant.
      TransferRequest original = new TransferRequest(
          "ACC-001", "ACC-002", new BigDecimal("100.00"), "USD", "rent"
      );
      TransferRequest differentAmount = new TransferRequest(
          "ACC-001", "ACC-002", new BigDecimal("200.00"), "USD", "rent"
      );

      when(idempotencyKeyRepository.save(any(IdempotencyKey.class)))
          .thenAnswer(inv -> inv.getArgument(0));

      service.reserveKey("key-A", 1L, TRANSFER_OPERATION, original);
      service.reserveKey("key-B", 1L, TRANSFER_OPERATION, differentAmount);

      ArgumentCaptor<IdempotencyKey> keyCaptor = ArgumentCaptor.forClass(IdempotencyKey.class);
      verify(idempotencyKeyRepository, times(2)).save(keyCaptor.capture());

      List<IdempotencyKey> savedKeys = keyCaptor.getAllValues();
      assertNotEquals(savedKeys.get(0).getRequestHash(), savedKeys.get(1).getRequestHash(),
          "Different transfer amounts must produce different hashes");
    }

    @Test
    @DisplayName("The operation scope is part of the idempotency fingerprint")
    void shouldProduceDifferentHashesForDifferentOperationScopes() {
      AccountOperationRequest sameBody = new AccountOperationRequest(
          new BigDecimal("100.00"), "memo"
      );

      when(idempotencyKeyRepository.save(any(IdempotencyKey.class)))
          .thenAnswer(inv -> inv.getArgument(0));

      service.reserveKey("key-A", 1L, "accounts.deposit", sameBody);
      service.reserveKey("key-B", 1L, "accounts.withdraw", sameBody);

      ArgumentCaptor<IdempotencyKey> keyCaptor = ArgumentCaptor.forClass(IdempotencyKey.class);
      verify(idempotencyKeyRepository, times(2)).save(keyCaptor.capture());

      List<IdempotencyKey> savedKeys = keyCaptor.getAllValues();
      assertNotEquals(savedKeys.get(0).getRequestHash(), savedKeys.get(1).getRequestHash(),
          "Deposit and withdraw must not share a fingerprint when the body is identical");
    }
  }

  @Nested
  @DisplayName("Key reuse handling — locked existing-row resolution")
  class KeyReuseHandling {

    @Test
    @DisplayName("Reusing a key with a different request body is rejected")
    void shouldRejectKeyReuseWithDifferentRequest() {
      // Same key, different body — a client bug or a malicious replay; either way it must never
      // be accepted silently as a legitimate retry.
      TransferRequest first = new TransferRequest(
          "ACC-001", "ACC-002", new BigDecimal("100.00"), "USD", "rent"
      );
      TransferRequest second = new TransferRequest(
          "ACC-001", "ACC-002", new BigDecimal("999.00"), "USD", "rent"
      );

      // Capture the Fresh entity so the retry compares against first's real canonical hash,
      // not a hand-made one.
      when(idempotencyKeyRepository.save(any(IdempotencyKey.class)))
          .thenAnswer(inv -> inv.getArgument(0));

      ReservationOutcome firstOutcome = service.reserveKey("key-shared", 1L, TRANSFER_OPERATION, first);
      IdempotencyKey existing = assertInstanceOf(ReservationOutcome.Fresh.class, firstOutcome).key();

      when(idempotencyKeyRepository.findByKeyValueAndUserIdForUpdate("key-shared", 1L))
          .thenReturn(Optional.of(existing));

      BusinessException ex = assertThrows(BusinessException.class,
          () -> service.reserveKey("key-shared", 1L, TRANSFER_OPERATION, second));
      // The exact message is client-visible contract (it becomes the ProblemDetail detail field).
      assertEquals("Idempotency key already used with different request parameters", ex.getMessage());
    }

    @Test
    @DisplayName("Reusing a key with the same request returns a Replay outcome with the cached body")
    void shouldReturnReplayWhenHashMatchesAndStatusIsCompleted() {
      TransferRequest request = new TransferRequest(
          "ACC-001", "ACC-002", new BigDecimal("100.00"), "USD", "rent"
      );

      when(idempotencyKeyRepository.save(any(IdempotencyKey.class)))
          .thenAnswer(inv -> inv.getArgument(0));

      ReservationOutcome firstOutcome = service.reserveKey("key-retry", 1L, TRANSFER_OPERATION, request);
      IdempotencyKey reserved = assertInstanceOf(ReservationOutcome.Fresh.class, firstOutcome).key();
      // In production the transfer flow performs this mutation inside its own transaction; here
      // it stages the retry scenario (not expired, COMPLETED, body cached).
      reserved.setId(77L);
      reserved.setStatus(IdempotencyKeyStatus.COMPLETED);
      reserved.setResponseBody("{\"cached\":true}");

      when(idempotencyKeyRepository.findByKeyValueAndUserIdForUpdate("key-retry", 1L))
          .thenReturn(Optional.of(reserved));

      ReservationOutcome result = service.reserveKey("key-retry", 1L, TRANSFER_OPERATION, request);

      ReservationOutcome.Replay replay = assertInstanceOf(ReservationOutcome.Replay.class, result);
      assertEquals(77L, replay.keyId(), "Replay must carry the id of the existing row for log correlation");
      assertEquals("{\"cached\":true}", replay.cachedResponseBody(),
          "Replay must expose the cached body verbatim — no transformation");
      // The replay must not re-insert: the only save is the seed insert.
      verify(idempotencyKeyRepository, times(1)).save(any(IdempotencyKey.class));
    }

    @Test
    @DisplayName("Reusing a key whose original response was lost is rejected with a domain exception")
    void shouldRejectReplayWhenStoredBodyIsNull() {
      // The Replay variant guarantees a non-null body by contract: a COMPLETED row whose body
      // was lost (best-effort null after a failed serialize) must reject the retry inside
      // reserveKey — the client never receives "ok but empty".
      TransferRequest request = new TransferRequest(
          "ACC-001", "ACC-002", new BigDecimal("100.00"), "USD", "rent"
      );

      when(idempotencyKeyRepository.save(any(IdempotencyKey.class)))
          .thenAnswer(inv -> inv.getArgument(0));

      ReservationOutcome firstOutcome = service.reserveKey("key-noresp", 1L, TRANSFER_OPERATION, request);
      IdempotencyKey reserved = assertInstanceOf(ReservationOutcome.Fresh.class, firstOutcome).key();
      reserved.setStatus(IdempotencyKeyStatus.COMPLETED);
      reserved.setResponseBody(null);

      when(idempotencyKeyRepository.findByKeyValueAndUserIdForUpdate("key-noresp", 1L))
          .thenReturn(Optional.of(reserved));

      BusinessException ex = assertThrows(BusinessException.class,
          () -> service.reserveKey("key-noresp", 1L, TRANSFER_OPERATION, request));
      assertEquals(
          "Original response no longer available for this idempotency key. Use a new key to retry.",
          ex.getMessage()
      );
    }

    @Test
    @DisplayName("An expired key is reclaimed as a fresh reservation, even with a different body")
    void shouldReclaimExpiredKeyAsFreshReservation() {
      // TTL semantics: an expired key is reusable as if it never existed — even with a different
      // body, which is why the expiry check precedes the hash check (a dead row must not act as
      // a same-key-different-body oracle). The row is reclaimed in place: same id, reset to
      // PENDING, new hash, new TTL, body cleared.
      TransferRequest differentBody = new TransferRequest(
          "ACC-001", "ACC-002", new BigDecimal("777.00"), "USD", "rent"
      );
      IdempotencyKey expired = IdempotencyKey.builder()
          .keyValue("key-expired")
          .userId(1L)
          .requestHash("a-stale-hash-from-a-different-request")
          .status(IdempotencyKeyStatus.COMPLETED)
          .responseBody("{\"stale\":true}")
          .expiresAt(Instant.now().minusSeconds(60))   // already past its TTL
          .build();
      expired.setId(55L);

      when(idempotencyKeyRepository.findByKeyValueAndUserIdForUpdate("key-expired", 1L))
          .thenReturn(Optional.of(expired));
      when(idempotencyKeyRepository.save(any(IdempotencyKey.class)))
          .thenAnswer(inv -> inv.getArgument(0));

      ReservationOutcome result = service.reserveKey("key-expired", 1L, TRANSFER_OPERATION, differentBody);

      IdempotencyKey reclaimed = assertInstanceOf(ReservationOutcome.Fresh.class, result).key();
      assertEquals(IdempotencyKeyStatus.PENDING, reclaimed.getStatus(), "reclaim resets status to PENDING");
      assertNull(reclaimed.getResponseBody(), "reclaim clears the stale cached body");
      assertTrue(reclaimed.getExpiresAt().isAfter(Instant.now()), "reclaim sets a fresh future TTL");
      assertNotEquals("a-stale-hash-from-a-different-request", reclaimed.getRequestHash(),
          "reclaim adopts the new request's fingerprint");
      verify(idempotencyKeyRepository).save(reclaimed);
    }

    @Test
    @DisplayName("Losing the concurrent first-insert race reports in-progress without querying")
    void shouldReportInProgressWhenInsertRaceLost() {
      // Concurrency edge: two first requests for a new key. Neither sees the other's row
      // (findForUpdate → empty), both INSERT, one violates the UNIQUE constraint. The loser
      // must not run a recovery query — its transaction is already aborted — so it reports
      // in-progress and rolls back while the winner keeps the PENDING reservation.
      TransferRequest request = new TransferRequest(
          "ACC-001", "ACC-002", new BigDecimal("100.00"), "USD", "rent"
      );
      when(idempotencyKeyRepository.save(any(IdempotencyKey.class)))
          .thenThrow(new DataIntegrityViolationException("unique constraint"));

      BusinessException ex = assertThrows(BusinessException.class,
          () -> service.reserveKey("key-race", 1L, TRANSFER_OPERATION, request));
      assertEquals("Operation already in progress for this idempotency key. Please wait.", ex.getMessage());
    }
  }
}
