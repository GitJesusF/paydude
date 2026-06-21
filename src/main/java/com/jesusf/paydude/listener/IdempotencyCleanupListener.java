package com.jesusf.paydude.listener;

import com.jesusf.paydude.event.IdempotencyKeyReservedEvent;
import com.jesusf.paydude.service.IdempotencyKeyService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Marks an idempotency key {@code FAILED} when the operation it reserved rolls back.
 *
 * <p>The key reservation runs in {@code REQUIRES_NEW}, so the {@code PENDING} row commits and
 * survives even when the surrounding money-moving transaction is rolled back. Without cleanup
 * that row would be stuck {@code PENDING} forever and block every retry. This listener closes
 * the loop: it reacts at {@code AFTER_ROLLBACK} and flips the key to {@code FAILED}, which lets
 * the client retry with a fresh key.
 */
@RequiredArgsConstructor
@Component
public class IdempotencyCleanupListener {

  private final IdempotencyKeyService idempotencyKeyService;

  /**
   * Flips the reserved key to {@code FAILED} after the outer transaction rolls back.
   *
   * <p>{@code markAsFailed} itself runs in {@code REQUIRES_NEW}: the rollback already discarded
   * the original transaction, so the status update needs a transaction of its own to commit.
   *
   * @param event the event carrying the id of the key that was reserved
   */
  @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK)
  public void releaseKeyOnFailure(IdempotencyKeyReservedEvent event) {
    idempotencyKeyService.markAsFailed(event.idempotencyKeyId());
  }
}
