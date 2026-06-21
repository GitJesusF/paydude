package com.jesusf.paydude.listener;

import com.jesusf.paydude.event.IdempotencyKeyReservedEvent;
import com.jesusf.paydude.service.IdempotencyKeyService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link IdempotencyCleanupListener}.
 *
 * <p>This listener is half of the idempotency-key safety net: when a transfer rolls back, the
 * reserved key must be flipped from {@code PENDING} to {@code FAILED} so the client can retry
 * with a fresh key (or the same key, knowing the previous attempt failed cleanly). In
 * production the framework drives that by listening at {@code AFTER_ROLLBACK} and running the
 * cleanup in a new transaction; here we only pin the delegation contract. The transactional
 * phases themselves are exercised in the integration tests, where a real transfer can roll back.
 */
@ExtendWith(MockitoExtension.class)
class IdempotencyCleanupListenerTest {

  @Mock
  private IdempotencyKeyService idempotencyKeyService;

  @InjectMocks
  private IdempotencyCleanupListener listener;

  @Test
  @DisplayName("after rollback, marks the reserved idempotency key as FAILED")
  void marksKeyAsFailedAfterRollback() {
    IdempotencyKeyReservedEvent event = new IdempotencyKeyReservedEvent(99L);

    // Direct handler invocation — production goes through Spring's event bus reflection.
    listener.releaseKeyOnFailure(event);

    // The key id must pass through untransformed to markAsFailed.
    verify(idempotencyKeyService).markAsFailed(99L);
  }
}
