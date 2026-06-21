package com.jesusf.paydude.security.ratelimit;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.config.properties.SecurityProperties.RateLimit;
import com.jesusf.paydude.config.properties.SecurityProperties.RateLimit.Bucket;
import com.jesusf.paydude.exception.RateLimitExceededException;
import com.jesusf.paydude.support.SecurityPropertiesFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link ReauthRateLimiter}.
 *
 * <p>This limiter is the only bound on password guessing through the authenticated re-authentication
 * gates (change-password, MFA setup/disable): those endpoints re-verify the account password but are
 * covered by neither the per-IP {@code IpRateLimitFilter} nor the per-email {@code AuthRateLimiter},
 * so if its consume contract drifts a stolen token could brute-force the password at BCrypt speed.
 * Three properties are pinned: a per-user bucket rejects past capacity, buckets are independent
 * across users, and {@code enforceReauthByUser} translates an exhausted bucket into the
 * {@link RateLimitExceededException} the controllers rely on (→ HTTP 429 + {@code Retry-After}).
 *
 * <p>Caffeine eviction timing is intentionally not covered (it would need a fake ticker for a
 * property the library already guarantees); what matters here is the consume semantics the
 * controllers depend on — the same scope as {@link WriteRateLimiterTest}.
 */
class ReauthRateLimiterTest {

  // Capacity is tiny so a few iterations drain the bucket; the period only sizes Caffeine's
  // eviction window — never waited on here.
  private static final int REAUTH_CAPACITY = 4;

  private ReauthRateLimiter limiter;

  @BeforeEach
  void setUp() {
    Bucket reauthBucket = new Bucket(REAUTH_CAPACITY, Duration.ofMinutes(15));
    // ReauthRateLimiter never reads the other buckets; the fillers only satisfy the RateLimit
    // record's Jakarta validation. reauthByUser is the seventh (last) field.
    Bucket filler = new Bucket(99, Duration.ofMinutes(1));
    SecurityProperties props = SecurityPropertiesFixture.withRateLimit(
        new RateLimit(filler, filler, filler, filler, filler, filler, reauthBucket)
    );
    limiter = new ReauthRateLimiter(props);
  }

  @Test
  @DisplayName("allows up to capacity for a user, then blocks the next re-auth")
  void allowsUpToCapacityThenBlocks() {
    Long userId = 1L;

    for (int i = 1; i <= REAUTH_CAPACITY; i++) {
      assertTrue(limiter.tryReauthByUser(userId), "re-auth " + i + " should be allowed");
    }
    assertFalse(limiter.tryReauthByUser(userId), "first re-auth past capacity must be rejected");
  }

  @Test
  @DisplayName("each user has its own independent bucket")
  void bucketsAreIndependentPerUser() {
    Long userA = 1L;
    Long userB = 2L;

    for (int i = 0; i < REAUTH_CAPACITY; i++) {
      limiter.tryReauthByUser(userA);
    }
    assertFalse(limiter.tryReauthByUser(userA), "userA is exhausted");

    // Proves the keying is genuinely per-user, not global — one throttled account must not
    // affect any other.
    assertTrue(limiter.tryReauthByUser(userB), "userB must not be affected by userA's bucket");
  }

  @Test
  @DisplayName("enforceReauthByUser throws RateLimitExceededException once the bucket is exhausted")
  void enforceThrowsWhenExhausted() {
    Long userId = 7L;

    for (int i = 0; i < REAUTH_CAPACITY; i++) {
      assertDoesNotThrow(() -> limiter.enforceReauthByUser(userId, "within budget"));
    }

    RateLimitExceededException ex = assertThrows(RateLimitExceededException.class,
        () -> limiter.enforceReauthByUser(userId, "too many re-auth attempts"));
    // The message travels in the problem+json body, the back-off in the Retry-After header.
    assertEquals("too many re-auth attempts", ex.getMessage());
    assertTrue(ex.getRetryAfterSeconds() > 0, "Retry-After hint must be positive");
  }
}
