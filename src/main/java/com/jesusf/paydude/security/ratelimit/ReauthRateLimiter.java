package com.jesusf.paydude.security.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.exception.RateLimitExceededException;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Service;

/**
 * In-memory token-bucket rate limiter for the password-re-authentication gates on the authenticated
 * account-security endpoints — change-password ({@code PATCH /v1/users/me/password}), MFA setup and
 * MFA disable ({@code POST /v1/users/me/mfa/{setup,disable}}) — keyed by the authenticated user id.
 *
 * <p><b>Why this tier exists.</b> Those endpoints re-verify the account password even though the
 * caller already holds a valid bearer token, precisely so a <i>stolen</i> token cannot commit a
 * sensitive action (rotate the password, or enroll/remove the attacker's own authenticator =
 * account takeover). But unlike {@code POST /v1/auth/login}, they sit behind authentication and are
 * therefore covered by neither {@link IpRateLimitFilter} (which runs pre-auth and keys by IP) nor
 * the per-email {@link AuthRateLimiter}. Without a bound here, a token holder who does not know the
 * password could brute-force it through these gates at BCrypt speed, undoing the whole point of the
 * re-authentication step. This limiter closes that gap.
 *
 * <p><b>Throttle, not lockout.</b> A wrong password here raises a 429 rather than tripping the
 * persistent account lockout that login failures feed. The distinction is deliberate: feeding the
 * account lockout from a token-authenticated endpoint would let an attacker holding a token lock the
 * legitimate owner out of <i>login</i> — exactly when the owner needs to log in to revoke sessions
 * and change the password. A per-user throttle bounds the guess rate without taking away the owner's
 * ability to respond. The window mirrors {@code loginByEmail} (a password re-auth is as sensitive as
 * a login); see {@code application.security.rate-limit.reauth-by-user.*}.
 *
 * <p>Storage and scaling mirror {@link WriteRateLimiter}: per-user {@link Bucket} instances in a
 * {@code Caffeine} cache with {@code expireAfterAccess} matched to the refill period, capped by
 * {@code maximumSize}; single-instance by design, swap for a {@code bucket4j-redis}
 * {@code ProxyManager} when scaling horizontally with the public API unchanged.
 */
@Service
public class ReauthRateLimiter {

  // Client-facing back-off hint for a throttled re-auth attempt, in seconds. Matches the default
  // reauth-by-user window (15m); RFC 7231 §7.1.3 documents Retry-After as a "no earlier than"
  // suggestion, so it need not track a re-tuned period exactly.
  private static final long REAUTH_RETRY_AFTER_SECONDS = 900;

  private final Bandwidth reauthByUserBandwidth;
  private final Cache<String, Bucket> reauthUserBuckets;

  public ReauthRateLimiter(SecurityProperties securityProperties) {
    SecurityProperties.RateLimit.Bucket limit = securityProperties.rateLimit().reauthByUser();
    this.reauthByUserBandwidth = RateLimitBuckets.toBandwidth(limit);
    this.reauthUserBuckets = RateLimitBuckets.buildCache(limit.period());
  }

  /**
   * Consumes one token from the calling user's re-authentication bucket.
   *
   * @param userId the authenticated principal's id
   * @return {@code true} if the request is within the limit, {@code false} if throttled
   */
  public boolean tryReauthByUser(Long userId) {
    return reauthUserBuckets
        .get(String.valueOf(userId), k -> Bucket.builder().addLimit(reauthByUserBandwidth).build())
        .tryConsume(1);
  }

  /**
   * Enforces the per-user re-authentication throttle, short-circuiting with a
   * {@link RateLimitExceededException} — translated to HTTP 429 + {@code Retry-After} by
   * {@code RateLimitExceptionHandler} — when the caller's bucket is exhausted. The account-security
   * controllers call this before invoking the password-gated service method, so a brute-force burst
   * is cut off before it ever reaches the BCrypt comparison. One token is consumed per attempt
   * (success or failure); these are deliberate, low-frequency actions, so counting the occasional
   * legitimate success against the budget is immaterial next to bounding the failures.
   *
   * @param userId  the authenticated principal's id — the bucket key
   * @param message client-facing detail surfaced in the {@code application/problem+json} body
   * @throws RateLimitExceededException if the caller has no re-auth tokens left
   */
  public void enforceReauthByUser(Long userId, String message) {
    if (!tryReauthByUser(userId)) {
      throw new RateLimitExceededException(message, REAUTH_RETRY_AFTER_SECONDS);
    }
  }
}
