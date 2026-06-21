package com.jesusf.paydude.enums;

/**
 * Lifecycle states of a user account, mapped onto the Spring Security
 * {@code UserDetails} contract.
 *
 * <p>{@code SecurityUser} translates each state into the framework checks:
 * {@link #ACTIVE} passes all of them; {@link #LOCKED} fails
 * {@code isAccountNonLocked()}; {@link #SUSPENDED} and {@link #CLOSED} fail
 * {@code isEnabled()}. Persisted as a string and constrained by a {@code CHECK}
 * on the {@code users} table.
 */
public enum UserStatus {

  /** Fully operational — authentication and all operations permitted. */
  ACTIVE,

  /** Temporarily locked; surfaces as HTTP 423. */
  LOCKED,

  /** Disabled by an operator; surfaces as HTTP 403. */
  SUSPENDED,

  /** Terminal state — the user can no longer authenticate. */
  CLOSED
}
