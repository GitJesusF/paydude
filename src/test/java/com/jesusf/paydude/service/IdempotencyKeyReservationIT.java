package com.jesusf.paydude.service;

import com.jesusf.paydude.dto.idempotent.TransferRequest;
import com.jesusf.paydude.entity.IdempotencyKey;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.IdempotencyKeyStatus;
import com.jesusf.paydude.enums.Role;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.exception.BusinessException;
import com.jesusf.paydude.repository.IdempotencyKeyRepository;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.service.IdempotencyKeyService.ReservationOutcome;
import com.jesusf.paydude.support.TestcontainersConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration coverage for {@code reserveKey} against a real Postgres unique constraint — the
 * collision path the mocked unit test cannot prove and that no other IT exercises (they all use
 * fresh keys). The insert-first variant aborted the transaction on the UNIQUE violation and threw
 * a Hibernate {@code AssertionFailure} instead of recovering; the SELECT-first + row-lock design
 * resolves replay, conflict, and expiry-reclaim without ever tripping that path.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class IdempotencyKeyReservationIT {

  private static final String OPERATION = "transactions.transfer";

  @Autowired private IdempotencyKeyService idempotencyKeyService;
  @Autowired private IdempotencyKeyRepository idempotencyKeyRepository;
  @Autowired private UserRepository userRepository;

  @Test
  @DisplayName("re-reserving a COMPLETED key replays the cached body")
  void replayOnCompletedKey() {
    Long userId = newUser();
    TransferRequest request = new TransferRequest("ACC-1", "ACC-2", new BigDecimal("10.00"), "USD", "rent");
    String key = UUID.randomUUID().toString();

    ReservationOutcome.Fresh fresh = assertInstanceOf(ReservationOutcome.Fresh.class,
        idempotencyKeyService.reserveKey(key, userId, OPERATION, request));
    idempotencyKeyService.complete(fresh.key(), "{\"cached\":true}");

    ReservationOutcome second = idempotencyKeyService.reserveKey(key, userId, OPERATION, request);

    ReservationOutcome.Replay replay = assertInstanceOf(ReservationOutcome.Replay.class, second);
    assertEquals("{\"cached\":true}", replay.cachedResponseBody());
  }

  @Test
  @DisplayName("re-reserving with a different body on a live key is a 409 conflict, not a 500")
  void conflictOnDifferentBodyForLiveKey() {
    Long userId = newUser();
    String key = UUID.randomUUID().toString();
    idempotencyKeyService.reserveKey(key, userId, OPERATION,
        new TransferRequest("ACC-1", "ACC-2", new BigDecimal("10.00"), "USD", "rent"));

    // Same key, different body, row still live (PENDING) → BusinessException, not a 500 from a
    // poisoned session. This is the exact regression of the insert-first bug on Postgres.
    assertThrows(BusinessException.class, () -> idempotencyKeyService.reserveKey(key, userId, OPERATION,
        new TransferRequest("ACC-1", "ACC-2", new BigDecimal("999.00"), "USD", "rent")));
  }

  @Test
  @DisplayName("an expired key is reclaimed as a fresh reservation")
  void reclaimsExpiredKey() {
    Long userId = newUser();
    String key = UUID.randomUUID().toString();
    TransferRequest request = new TransferRequest("ACC-1", "ACC-2", new BigDecimal("10.00"), "USD", "rent");

    ReservationOutcome.Fresh first = assertInstanceOf(ReservationOutcome.Fresh.class,
        idempotencyKeyService.reserveKey(key, userId, OPERATION, request));
    idempotencyKeyService.complete(first.key(), "{\"cached\":true}");

    // Age the row below "now" to simulate an elapsed TTL without waiting on wall-clock.
    IdempotencyKey row = idempotencyKeyRepository.findById(first.key().getId()).orElseThrow();
    row.setExpiresAt(Instant.now().minusSeconds(60));
    idempotencyKeyRepository.saveAndFlush(row);

    ReservationOutcome reclaimed = idempotencyKeyService.reserveKey(key, userId, OPERATION, request);

    assertInstanceOf(ReservationOutcome.Fresh.class, reclaimed);
    IdempotencyKey after = idempotencyKeyRepository.findById(first.key().getId()).orElseThrow();
    assertEquals(IdempotencyKeyStatus.PENDING, after.getStatus(), "reclaim resets status to PENDING");
    assertNull(after.getResponseBody(), "reclaim clears the stale cached body");
    assertTrue(after.getExpiresAt().isAfter(Instant.now()), "reclaim sets a fresh future TTL");
  }

  @Test
  @DisplayName("an expired key can be reused with a different body")
  void reclaimsExpiredKeyBeforeHashComparison() {
    Long userId = newUser();
    String key = UUID.randomUUID().toString();
    TransferRequest original = new TransferRequest(
        "ACC-1", "ACC-2", new BigDecimal("10.00"), "USD", "rent"
    );
    TransferRequest differentBody = new TransferRequest(
        "ACC-1", "ACC-2", new BigDecimal("999.00"), "USD", "rent"
    );

    ReservationOutcome.Fresh first = assertInstanceOf(ReservationOutcome.Fresh.class,
        idempotencyKeyService.reserveKey(key, userId, OPERATION, original));
    idempotencyKeyService.complete(first.key(), "{\"cached\":true}");

    // Expiry is checked before hash comparison. Once the row is past TTL, the key is reusable
    // with any body and must not become a "same key, different body" oracle.
    IdempotencyKey row = idempotencyKeyRepository.findById(first.key().getId()).orElseThrow();
    row.setExpiresAt(Instant.now().minusSeconds(60));
    idempotencyKeyRepository.saveAndFlush(row);

    ReservationOutcome reclaimed = idempotencyKeyService.reserveKey(
        key, userId, OPERATION, differentBody
    );

    assertInstanceOf(ReservationOutcome.Fresh.class, reclaimed);
    IdempotencyKey after = idempotencyKeyRepository.findById(first.key().getId()).orElseThrow();
    assertEquals(IdempotencyKeyStatus.PENDING, after.getStatus(), "reclaim resets status to PENDING");
    assertNull(after.getResponseBody(), "reclaim clears the stale cached body");
    assertTrue(after.getExpiresAt().isAfter(Instant.now()), "reclaim sets a fresh future TTL");
  }

  private Long newUser() {
    return userRepository.save(User.builder()
        .firstName("Idem")
        .lastName("Potency")
        .email("idem-" + UUID.randomUUID() + "@test.com")
        .password("$2a$10$unusedHashOnlyNeededForNotNullColumn")
        .role(Role.ROLE_USER)
        .status(UserStatus.ACTIVE)
        .passwordChangedAt(Instant.now())
        .build()).getId();
  }
}
