package com.jesusf.paydude.service;

import com.jesusf.paydude.dto.user.MfaRecoveryCodesResponse;
import com.jesusf.paydude.dto.user.MfaSetupResponse;
import com.jesusf.paydude.entity.User;

/**
 * TOTP second-factor lifecycle (RFC 6238): enrollment, activation, removal, and code
 * verification. The companion to two flows that stay elsewhere on purpose — token minting after
 * a verified code lives in {@code AuthService.verifyMfa} (one place issues sessions), and the
 * step-up branch of the password stage lives in {@code AuthService.login}.
 *
 * <p>Enrollment is a deliberate two-phase commit: {@link #setup} generates and returns the secret
 * but arms nothing; only {@link #confirm} — by accepting a code the authenticator actually
 * produced — flips the account to MFA-required. Skipping the proof step would let a failed QR
 * scan lock the user out of every future login. {@link #setup} and {@link #disable} both demand
 * the account password: a stolen access token must be able neither to enroll an attacker's
 * authenticator (takeover) nor to strip the second factor off (downgrade).
 */
public interface MfaService {

  /** How a submitted second-factor proof fared, and which kind it was. */
  enum MfaVerification {
    /** A valid, not-yet-used TOTP code. */
    TOTP,
    /** A valid, previously unused recovery code — now consumed. */
    RECOVERY_CODE,
    /** Neither a valid TOTP (or a replayed one) nor a redeemable recovery code. */
    INVALID
  }

  /**
   * Starts enrollment: verifies the password, generates a fresh secret, stores it as
   * <b>pending</b> ({@code mfa_enabled} stays false) and returns the provisioning material.
   * Calling it again before {@code confirm} replaces the pending secret.
   *
   * @param userId   the authenticated user
   * @param password the account password (re-authentication)
   * @return the Base32 secret and {@code otpauth://} URI for the authenticator app
   */
  MfaSetupResponse setup(Long userId, String password);

  /**
   * Activates the pending enrollment: verifies a code computed from the pending secret, flips
   * {@code mfa_enabled} on, and issues the single-use recovery codes — returned in plaintext
   * exactly once, persisted only as SHA-256 digests.
   *
   * @param userId the authenticated user
   * @param code   a current 6-digit TOTP from the freshly-provisioned authenticator
   * @return the recovery codes for the lost-device path
   */
  MfaRecoveryCodesResponse confirm(Long userId, String code);

  /**
   * Disables the second factor after re-verifying the password: clears the secret and the replay
   * baseline, deletes every recovery code. Idempotent — disabling a non-enrolled account is a
   * no-op (the password is still verified first).
   *
   * @param userId   the authenticated user
   * @param password the account password (re-authentication)
   */
  void disable(Long userId, String password);

  /**
   * Verifies a second-factor proof during the login step-up. A 6-digit submission is checked as
   * TOTP (±1 step window, then the RFC 6238 §5.2 single-use guard); anything else is canonicalised
   * and redeemed as a recovery code (atomic single-use consume). Never throws for a wrong code —
   * the {@code INVALID} outcome lets the caller own the failure side-effects (lockout counting,
   * metrics, audit, the 401).
   *
   * @param user the MFA-enrolled user completing a login
   * @param code the submitted TOTP or recovery code
   * @return what the code turned out to be
   */
  MfaVerification verify(User user, String code);
}
