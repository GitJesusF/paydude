package com.jesusf.paydude.dto.auth;

/**
 * Outcome of the password stage of a login — either a finished session or a pending second
 * factor. {@code AuthService.login} returns this instead of a bare {@link AuthResponse} because,
 * with TOTP in the picture, a correct password no longer implies a session: for an MFA-enrolled
 * account it only earns a challenge.
 *
 * <p>Sealed for the same reason as {@code ReservationOutcome} in the idempotency layer: the
 * controller's {@code switch} over the permitted records is exhaustive, so adding a third outcome
 * (say, a WebAuthn challenge) is a compile error at every call site rather than a silently
 * unhandled branch.
 */
public sealed interface LoginResult {

  /** The login is complete (single-factor account): the token pair is ready to return. */
  record Tokens(AuthResponse tokens) implements LoginResult {}

  /**
   * The password was correct but the account is MFA-enrolled: the caller gets a challenge to
   * redeem at {@code POST /v1/auth/mfa/verify}, not a session.
   */
  record MfaRequired(MfaChallengeResponse challenge) implements LoginResult {}
}
