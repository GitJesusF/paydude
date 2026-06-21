package com.jesusf.paydude.event;

/**
 * Published once an idempotency key has been reserved for an in-flight operation.
 *
 * <p>{@code IdempotencyCleanupListener} consumes it at {@code AFTER_ROLLBACK}:
 * if the surrounding transaction rolls back, the listener flips the key from
 * {@code PENDING} to {@code FAILED}. Because the reservation runs in
 * {@code REQUIRES_NEW} the key row survives the rollback and is still there to
 * be marked.
 *
 * @param idempotencyKeyId the id of the reserved key row
 */
public record IdempotencyKeyReservedEvent(Long idempotencyKeyId) {
}
