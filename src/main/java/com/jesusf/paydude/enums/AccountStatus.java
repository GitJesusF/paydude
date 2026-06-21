package com.jesusf.paydude.enums;

/**
 * Lifecycle states of a bank account.
 *
 * <p>Only {@link #ACTIVE} accounts may take part in money movement; the service
 * layer rejects deposits, withdrawals and transfers against every other state.
 * Persisted as a string and constrained by a {@code CHECK} on the
 * {@code accounts} table.
 */
public enum AccountStatus {

  /** Operational — the only state that permits balance changes. */
  ACTIVE,

  /** Created but not yet activated for money movement. */
  PENDING,

  /** Temporarily blocked from money movement (operational or compliance hold). */
  FROZEN,

  /** Terminal state — the account can no longer be used. */
  CLOSED
}