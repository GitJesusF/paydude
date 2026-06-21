package com.jesusf.paydude.service;

import com.jesusf.paydude.entity.RefreshToken;

import java.time.Instant;

/**
 * Refresh-token lifecycle. Owns issuance, rotation, and revocation; the {@link RefreshToken}
 * entity is opaque to callers.
 *
 * <p>Single-use rotation with reuse detection (OAuth 2.1 mandate): every successful refresh
 * revokes the presented token and emits a new one in the same family. A second use of an
 * already-revoked token assumes compromise and revokes the entire family. The blast radius of a
 * stolen token is therefore one refresh cycle, not the token's nominal lifetime.
 */
public interface RefreshTokenService {

  /**
   * Issues the first refresh token of a new family. Called by {@code AuthService.login} and
   * {@code AuthService.register} immediately after the access token is minted.
   *
   * @param userId    Authenticated user id
   * @param clientIp  Captured for the audit row (already resolved via Tomcat's {@code RemoteIpValve})
   * @param userAgent Captured for the audit row (raw {@code User-Agent} header value, may be null)
   * @return The raw token (to embed in the response) and its expiry instant
   */
  IssuedRefreshToken issueNewFamily(Long userId, String clientIp, String userAgent);

  /**
   * Validates the presented refresh token, revokes it, and emits a new one in the same family.
   *
   * <p>Side effects in failure modes:
   * <ul>
   *   <li>If the presented token is unknown, expired, or belongs to a non-{@code ACTIVE} user →
   *       {@code BadCredentialsException}. No row mutated.</li>
   *   <li>If the presented token is found but already revoked → the entire family is revoked
   *       (reuse detection). {@code BadCredentialsException} surfaces to the client, while the
   *       service emits a WARN log including the family id.</li>
   * </ul>
   *
   * @return The new raw token + its expiry + the {@code userId} the caller will need to mint a
   *         fresh access JWT
   */
  RotatedTokens rotate(String rawRefreshToken, String clientIp, String userAgent);

  /**
   * Revokes every still-active token in the family of the presented token. Idempotent and
   * lenient: unknown or already-revoked tokens are silent no-ops (a logout call must always
   * succeed from the client's perspective, even if the token was already invalidated by
   * another path).
   */
  void revokeFamily(String rawRefreshToken);

  /**
   * Revokes every still-active token belonging to {@code userId}, across all their families —
   * forcing re-login on every device. Invoked by the password-change flow
   * ({@code PATCH /v1/users/me/password} &rarr; {@code UserServiceImpl.changePassword}); also the
   * intended hook for admin-driven "force logout from all devices".
   */
  void revokeAllForUser(Long userId);

  /**
   * Bulk-deletes every token whose lifetime has elapsed ({@code expiresAt < cutoff}). Invoked by
   * the scheduled cleanup job. An expired token can no longer authenticate, so its row is dead
   * weight; revoked-but-unexpired rows are left in place for the forensic audit window.
   *
   * @param cutoff rows with {@code expiresAt} strictly before this instant are removed
   * @return the number of rows deleted
   */
  int deleteExpired(Instant cutoff);

  /**
   * Result of {@link #issueNewFamily}: the raw, unhashed token to return to the client plus its
   * expiry. The hashed form is already persisted by the time this returns.
   */
  record IssuedRefreshToken(String rawToken, Instant expiresAt) {}

  /**
   * Result of {@link #rotate}: the new raw refresh token, its expiry, and the user id the
   * caller needs to mint a fresh access JWT.
   */
  record RotatedTokens(String rawRefreshToken, Instant refreshExpiresAt, Long userId) {}
}