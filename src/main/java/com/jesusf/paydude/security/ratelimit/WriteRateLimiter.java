package com.jesusf.paydude.security.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.exception.RateLimitExceededException;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Service;

/**
 * In-memory token-bucket rate limiter for the money-moving write endpoints — deposit, withdraw
 * and transfer — keyed by the authenticated user id.
 *
 * <p>This is the authenticated-write counterpart to {@link AuthRateLimiter}. Where the auth tier
 * throttles unauthenticated brute-force by IP and email, these endpoints sit behind a bearer
 * token, so the abuse that matters is a single authenticated principal replaying writes: each one
 * inserts an {@code idempotency_keys} row, a {@code transactions} row and two {@code account_audits}
 * rows, and takes a pessimistic lock on the caller's account. Left unbounded, one account can grow
 * DB state without limit and keep the row locks busy. Keying by user id (not IP) is deliberate —
 * the caller is already identified, rotating the source IP must not reset the budget, and legitimate
 * clients behind shared NAT must not share one.
 *
 * <p>The check lives in the controllers (the business tier), not in {@link IpRateLimitFilter}: the
 * filter runs before Spring Security and has no authenticated principal, so it cannot key by user.
 * All three write endpoints share a single per-user bucket — the concern is aggregate write volume
 * per account, not per individual operation.
 *
 * <p>Storage mirrors {@link AuthRateLimiter}: per-user {@link Bucket} instances live in a
 * {@code Caffeine} cache with {@code expireAfterAccess} matched to the refill period (a user idle
 * for one full period has a bucket refilled to capacity, so evicting it is indistinguishable from
 * keeping it), and {@code maximumSize} caps memory under a spray of distinct ids. Single-instance
 * by design; horizontal scaling swaps the cache for a {@code bucket4j-redis} {@code ProxyManager}
 * with the public API unchanged.
 *
 * <p>The threshold is configurable via {@code application.security.rate-limit.write-by-user.*},
 * bound through {@link SecurityProperties.RateLimit}, validated at boot, and visible at
 * {@code /actuator/configprops} — so operators can tighten it during an incident without a redeploy.
 */
@Service
public class WriteRateLimiter {

  // Client-facing back-off hint for a throttled write, in seconds. Matches the default
  // write-by-user refill window (1m); RFC 7231 §7.1.3 documents Retry-After as a "no earlier than"
  // suggestion, so it does not need to track a re-tuned period exactly.
  private static final long WRITE_RETRY_AFTER_SECONDS = 60;

  private final Bandwidth writeByUserBandwidth;
  private final Cache<String, Bucket> writeUserBuckets;

  public WriteRateLimiter(SecurityProperties securityProperties) {
    SecurityProperties.RateLimit.Bucket limit = securityProperties.rateLimit().writeByUser();
    this.writeByUserBandwidth = RateLimitBuckets.toBandwidth(limit);
    this.writeUserBuckets = RateLimitBuckets.buildCache(limit.period());
  }

  /**
   * Consumes one token from the calling user's write bucket.
   *
   * @param userId the authenticated principal's id
   * @return {@code true} if the request is within the limit, {@code false} if throttled
   */
  public boolean tryWriteByUser(Long userId) {
    return writeUserBuckets
        .get(String.valueOf(userId), k -> Bucket.builder().addLimit(writeByUserBandwidth).build())
        .tryConsume(1);
  }

  /**
   * Enforces the per-user write throttle, short-circuiting with a {@link RateLimitExceededException}
   * — translated to HTTP 429 + {@code Retry-After} by {@code RateLimitExceptionHandler} — when the
   * caller's bucket is exhausted. The money-moving write controllers call this before any service
   * or database work; keying by the authenticated principal (not the IP) is the whole point of this
   * tier, so the check belongs behind authentication rather than in {@link IpRateLimitFilter}.
   *
   * @param userId  the authenticated principal's id — the bucket key
   * @param message client-facing detail surfaced in the {@code application/problem+json} body
   * @throws RateLimitExceededException if the caller has no write tokens left
   */
  public void enforceWriteByUser(Long userId, String message) {
    if (!tryWriteByUser(userId)) {
      throw new RateLimitExceededException(message, WRITE_RETRY_AFTER_SECONDS);
    }
  }
}
