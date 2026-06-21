package com.jesusf.paydude.enums;

/**
 * The kind of security-relevant event captured in the {@code security_audit_events} table.
 *
 * <p>Persisted as a string ({@code @Enumerated(EnumType.STRING)}) and pinned by a CHECK constraint
 * in {@code V0_003}, so adding a value requires a migration that widens that constraint. Every row
 * pairs an event type with a {@link SecurityAuditOutcome} (the result) — e.g. {@code LOGIN} +
 * {@code FAILURE}.
 */
public enum SecurityAuditEventType {

  /** Authentication attempt at {@code POST /v1/auth/login}. */
  LOGIN,

  /** Session/family revocation at {@code POST /v1/auth/logout}. */
  LOGOUT,

  /** New account created at {@code POST /v1/auth/register}. */
  REGISTER,

  /** Password change at {@code PATCH /v1/users/me/password}. */
  PASSWORD_CHANGE,

  /** Account transitioned to {@code LOCKED} by the anti-bruteforce policy. */
  ACCOUNT_LOCKED,

  /** A revoked refresh token was replayed; the whole family was revoked (possible token theft). */
  TOKEN_REUSE_DETECTED,

  /**
   * Password stage passed for an MFA-enrolled account; a challenge token was issued. A
   * {@code MFA_CHALLENGE} with no subsequent {@code LOGIN}/{@code SUCCESS} is the forensic
   * signature of a compromised password stopped by the second factor.
   */
  MFA_CHALLENGE,

  /** TOTP second factor activated at {@code POST /v1/users/me/mfa/confirm} (or attempt failed). */
  MFA_ENABLED,

  /** TOTP second factor removed at {@code POST /v1/users/me/mfa/disable} (or attempt failed). */
  MFA_DISABLED
}
