package com.jesusf.paydude.security.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.jesusf.paydude.config.properties.SecurityProperties;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;

import java.time.Duration;

/**
 * Shared construction helpers for the in-memory token-bucket rate limiters
 * ({@link AuthRateLimiter}, {@link WriteRateLimiter}, {@link ReauthRateLimiter}).
 *
 * <p>Each limiter stores per-key {@link Bucket} instances in a {@link Caffeine} cache and translates
 * the typed {@link SecurityProperties.RateLimit.Bucket} configuration into a bucket4j
 * {@link Bandwidth}. The two routines are identical, so they live here once rather than being
 * copy-pasted into each limiter.
 */
final class RateLimitBuckets {

  /**
   * Defensive upper bound on the number of distinct keys (IPs, emails, user ids) a single cache may
   * hold at once. Caps worst-case memory during a spray of distinct keys, before
   * {@code expireAfterAccess} eviction catches up.
   */
  static final long MAX_BUCKETS_PER_CACHE = 100_000;

  private RateLimitBuckets() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }

  /**
   * Builds the per-key bucket cache. {@code expireAfterAccess(period)} is the right window: after
   * one full silent period the bucket has refilled to capacity (per {@code refillIntervally}), so an
   * evicted-and-recreated entry is indistinguishable from a retained one. {@code maximumSize} is a
   * defensive cap for the window between bursty access and eviction sweeping.
   *
   * @param evictionPeriod the bucket's refill period; doubles as the idle-eviction window
   * @return a configured, empty cache of per-key buckets
   */
  static Cache<String, Bucket> buildCache(Duration evictionPeriod) {
    return Caffeine.newBuilder()
        .expireAfterAccess(evictionPeriod)
        .maximumSize(MAX_BUCKETS_PER_CACHE)
        .build();
  }

  /**
   * Translates the type-safe {@link SecurityProperties.RateLimit.Bucket} into the bucket4j
   * {@link Bandwidth} that the runtime expects. The configured capacity doubles as the refill amount
   * per period — there is no operational use case here for capacity and refill to diverge, so the
   * API stays a single number.
   *
   * @param bucket the typed bucket configuration (capacity + period)
   * @return the equivalent bucket4j bandwidth
   */
  static Bandwidth toBandwidth(SecurityProperties.RateLimit.Bucket bucket) {
    return Bandwidth.builder()
        .capacity(bucket.capacity())
        .refillIntervally(bucket.capacity(), bucket.period())
        .build();
  }
}
