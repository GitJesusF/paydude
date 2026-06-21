package com.jesusf.paydude.service;

import com.jesusf.paydude.dto.auth.AuthResponse;
import com.jesusf.paydude.dto.auth.LoginRequest;
import com.jesusf.paydude.dto.auth.LoginResult;
import com.jesusf.paydude.dto.auth.MfaVerifyRequest;
import com.jesusf.paydude.dto.auth.RegisterRequest;

/**
 * Authentication and session lifecycle: registration, login, refresh-token rotation, and logout.
 *
 * <p>Every entry point that mints tokens issues an OAuth-style {@code AuthResponse} carrying a
 * short-lived access token and a long-lived, single-use refresh token. The {@code clientIp} and
 * {@code userAgent} parameters are not used for authorization — they are captured into the
 * refresh-token audit row so a suspected token-reuse incident can be investigated.
 */
public interface AuthService {

  /**
   * Registers a new user and mints the first access + refresh pair. The refresh token is the
   * head of a fresh family; subsequent rotations stay within that family until logout, reuse
   * detection, or natural expiry close it.
   *
   * @param clientIp  Resolved peer IP — captured for the refresh-token audit row
   * @param userAgent Raw {@code User-Agent} header — captured for the refresh-token audit row
   */
  AuthResponse register(RegisterRequest request, String clientIp, String userAgent);

  /**
   * Authenticates the credentials. For a single-factor account this mints the first access +
   * refresh pair of a new session family ({@link LoginResult.Tokens}); for an MFA-enrolled
   * account a correct password earns only a short-lived challenge token
   * ({@link LoginResult.MfaRequired}) — the session is minted by {@link #verifyMfa} once the
   * second factor is proven. The same notes about audit fields apply as {@link #register}.
   */
  LoginResult login(LoginRequest request, String clientIp, String userAgent);

  /**
   * Completes a step-up login: validates the challenge token from {@link #login}, verifies the
   * TOTP or recovery code, and only then mints the access + refresh pair. Failed codes feed the
   * same persistent lockout as failed passwords.
   */
  AuthResponse verifyMfa(MfaVerifyRequest request, String clientIp, String userAgent);

  /**
   * Validates the presented refresh token, rotates it, and mints a fresh access token for the
   * same user. The previous refresh token is revoked; any subsequent attempt to reuse it
   * triggers family-wide revocation.
   */
  AuthResponse refresh(String rawRefreshToken, String clientIp, String userAgent);

  /**
   * Revokes the family of the presented refresh token. Idempotent — an unknown or already
   * revoked token is a successful logout from the client's perspective.
   */
  void logout(String rawRefreshToken);
}