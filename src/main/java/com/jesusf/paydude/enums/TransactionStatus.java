package com.jesusf.paydude.enums;

/**
 * Lifecycle states of a transaction.
 *
 * <p>Transfers in this codebase are synchronous and atomic, so they are
 * persisted directly as {@link #COMPLETED}. The remaining states model an
 * asynchronous settlement pipeline (pending authorization, processing holds,
 * reversals) that the schema is ready for but the current flow does not yet
 * exercise.
 */
public enum TransactionStatus {

  /** Created, awaiting processing. */
  PENDING,

  /** Being settled. */
  PROCESSING,

  /** Held — for example pending fraud or compliance review. */
  FROZEN,

  /** Settled successfully; the terminal state of every current transfer. */
  COMPLETED,

  /** Settlement failed. */
  FAILED,

  /** A previously completed transaction was undone. */
  REVERSED
}