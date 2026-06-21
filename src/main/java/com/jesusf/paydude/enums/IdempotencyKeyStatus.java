package com.jesusf.paydude.enums;

/**
 * Lifecycle of an idempotency key reservation.
 *
 * <p>The transition graph is {@code PENDING → COMPLETED | FAILED}. A key is
 * inserted as {@link #PENDING} when an idempotent operation is reserved; it
 * moves to {@link #COMPLETED} once the operation commits (with the cached
 * response body), or to {@link #FAILED} if the surrounding transaction rolls
 * back. A retry under the same key branches on this status.
 */
public enum IdempotencyKeyStatus {

  /** Operation reserved and in progress; a concurrent retry is rejected. */
  PENDING,

  /** Operation succeeded; retries replay the cached response body. */
  COMPLETED,

  /** Operation rolled back; retries are rejected and must use a fresh key. */
  FAILED
}