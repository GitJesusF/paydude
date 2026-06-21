package com.jesusf.paydude.security.ratelimit;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.config.properties.SecurityProperties.RateLimit;
import com.jesusf.paydude.config.properties.SecurityProperties.RateLimit.Bucket;
import com.jesusf.paydude.support.SecurityPropertiesFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link WriteRateLimiter}.
 *
 * <p>This limiter is the only bound on authenticated write abuse: the IP-keyed auth throttles do
 * not cover deposit/withdraw/transfer, so if its consume contract drifts, a single account can grow
 * DB state and hold account row-locks without limit. Two properties are pinned: a per-user bucket
 * rejects past capacity, and buckets are independent across users (so one abuser cannot starve
 * everyone else, and — the inverse — keying is genuinely per-user rather than global).
 *
 * <p>Caffeine eviction timing is intentionally not covered (it would need a fake ticker for a
 * property the library already guarantees); what matters here is the consume semantics the
 * controllers depend on.
 */
class WriteRateLimiterTest {

  // Capacity is tiny so a few iterations drain the bucket; the period only sizes Caffeine's
  // eviction window — never waited on here.
  private static final int WRITE_CAPACITY = 4;

  private WriteRateLimiter limiter;

  @BeforeEach
  void setUp() {
    Bucket writeBucket = new Bucket(WRITE_CAPACITY, Duration.ofMinutes(1));
    // WriteRateLimiter never reads the auth buckets (mfa-by-ip included); the fillers only have
    // to satisfy the RateLimit record's Jakarta validation.
    Bucket filler = new Bucket(99, Duration.ofMinutes(1));
    SecurityProperties props = SecurityPropertiesFixture.withRateLimit(
        new RateLimit(filler, filler, filler, filler, writeBucket, filler, filler)
    );
    limiter = new WriteRateLimiter(props);
  }

  @Test
  @DisplayName("allows up to capacity for a user, then blocks the next write")
  void allowsUpToCapacityThenBlocks() {
    Long userId = 1L;

    for (int i = 1; i <= WRITE_CAPACITY; i++) {
      assertTrue(limiter.tryWriteByUser(userId), "write " + i + " should be allowed");
    }
    assertFalse(limiter.tryWriteByUser(userId), "first write past capacity must be rejected");
  }

  @Test
  @DisplayName("each user has its own independent bucket")
  void bucketsAreIndependentPerUser() {
    Long userA = 1L;
    Long userB = 2L;

    for (int i = 0; i < WRITE_CAPACITY; i++) {
      limiter.tryWriteByUser(userA);
    }
    assertFalse(limiter.tryWriteByUser(userA), "userA is exhausted");

    assertTrue(limiter.tryWriteByUser(userB), "userB must not be affected by userA's bucket");
  }
}
