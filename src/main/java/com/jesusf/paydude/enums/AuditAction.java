package com.jesusf.paydude.enums;

/**
 * The kind of balance change recorded by an {@code AccountAudit} row.
 *
 * <p>{@link #DEPOSIT} and {@link #WITHDRAW} are single-account operations and
 * leave the audit's {@code transaction} reference null. {@link #TRANSFER_IN} and
 * {@link #TRANSFER_OUT} always come in pairs — one per side of a transfer — and
 * both reference the same {@code Transaction}.
 */
public enum AuditAction {

  /** Funds added to a single account. */
  DEPOSIT,

  /** Funds removed from a single account. */
  WITHDRAW,

  /** Credit side of a transfer (target account). */
  TRANSFER_IN,

  /** Debit side of a transfer (source account). */
  TRANSFER_OUT
}