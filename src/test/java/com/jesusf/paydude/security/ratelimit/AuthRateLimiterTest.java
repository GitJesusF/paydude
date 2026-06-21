package com.jesusf.paydude.security.ratelimit;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.config.properties.SecurityProperties.RateLimit;
import com.jesusf.paydude.config.properties.SecurityProperties.RateLimit.Bucket;
import com.jesusf.paydude.support.SecurityPropertiesFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link AuthRateLimiter}.
 *
 * <p>The rate limiter is the only thing standing between the {@code /auth/login} endpoint and a
 * brute-force / credential-stuffing attack, so its consume-and-refund contract must be exhaustively
 * pinned: each bucket must reject past capacity, buckets must be independent across keys and
 * operations, the email keying must be case-insensitive (otherwise toggling letter case bypasses
 * the limit), and a successful login must refund exactly one token without ever overshooting
 * capacity. The per-IP methods additionally return a {@link RateLimitSnapshot} (allowed + remaining
 * + reset) so the filter can publish the IETF {@code RateLimit} header.
 *
 * <p>Caffeine's eviction behaviour is intentionally <i>not</i> covered here: it would require a
 * fake ticker and slow, flaky timing assertions for a property already guaranteed by the library.
 * What matters at this layer is that the eviction window is wired (verified by reading
 * {@code AuthRateLimiter}) and that the consume/refund semantics the controller depends on are
 * correct — which is what the tests below assert.
 */
class AuthRateLimiterTest {

  // Capacities are deliberately tiny (≠ production defaults) so draining a bucket takes a few
  // iterations. The periods only size Caffeine's eviction window — never waited on here.
  private static final int LOGIN_IP_CAPACITY = 5;
  private static final int LOGIN_EMAIL_CAPACITY = 3;
  private static final int REGISTER_IP_CAPACITY = 2;
  private static final int REFRESH_IP_CAPACITY = 4;
  // The write-by-user bucket belongs to WriteRateLimiter, not AuthRateLimiter — this value is only
  // here to satisfy the RateLimit record's fifth field; nothing in this test consumes it.
  private static final int WRITE_USER_CAPACITY = 8;
  // Deliberately the smallest capacity: it backs the strictest bucket (checkMfaVerifyByIp).
  private static final int MFA_IP_CAPACITY = 3;
  // Likewise, the reauth-by-user bucket belongs to ReauthRateLimiter — placeholder for the record's
  // seventh field; nothing in this test consumes it.
  private static final int REAUTH_USER_CAPACITY = 6;

  private AuthRateLimiter limiter;

  @BeforeEach
  void setUp() {
    SecurityProperties props = SecurityPropertiesFixture.withRateLimit(new RateLimit(
        new Bucket(LOGIN_IP_CAPACITY, Duration.ofMinutes(1)),
        new Bucket(LOGIN_EMAIL_CAPACITY, Duration.ofMinutes(15)),
        new Bucket(REGISTER_IP_CAPACITY, Duration.ofHours(1)),
        new Bucket(REFRESH_IP_CAPACITY, Duration.ofHours(1)),
        new Bucket(WRITE_USER_CAPACITY, Duration.ofMinutes(1)),
        new Bucket(MFA_IP_CAPACITY, Duration.ofMinutes(1)),
        new Bucket(REAUTH_USER_CAPACITY, Duration.ofMinutes(15))
    ));
    limiter = new AuthRateLimiter(props);
  }

  // -----------------------------------------------------------------------------------------------
  // checkLoginByIp — generous bucket keyed by IP, returns a RateLimitSnapshot
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("checkLoginByIp() — consumes one token per attempt until capacity")
  class CheckLoginByIp {

    @Test
    @DisplayName("allows up to capacity, then blocks the next attempt")
    void allowsUpToCapacityThenBlocks() {
      String ip = "203.0.113.10";

      for (int i = 1; i <= LOGIN_IP_CAPACITY; i++) {
        assertTrue(limiter.checkLoginByIp(ip).allowed(), "attempt " + i + " should be allowed");
      }
      assertFalse(limiter.checkLoginByIp(ip).allowed(), "first attempt past capacity must be rejected");
    }

    @Test
    @DisplayName("each IP has its own independent bucket")
    void bucketsAreIndependentPerIp() {
      String ipA = "203.0.113.10";
      String ipB = "203.0.113.20";

      for (int i = 0; i < LOGIN_IP_CAPACITY; i++) {
        limiter.checkLoginByIp(ipA);
      }
      assertFalse(limiter.checkLoginByIp(ipA).allowed(), "ipA is exhausted");

      assertTrue(limiter.checkLoginByIp(ipB).allowed(), "ipB must not be affected by ipA's bucket");
    }

    @Test
    @DisplayName("snapshot reports decreasing remaining tokens and a non-negative reset")
    void snapshotReportsRemainingAndReset() {
      // The filter publishes these values as RateLimit: "login";r=<remaining>;t=<reset>.
      String ip = "203.0.113.30";

      RateLimitSnapshot first = limiter.checkLoginByIp(ip);
      RateLimitSnapshot second = limiter.checkLoginByIp(ip);

      assertTrue(first.allowed());
      assertTrue(second.allowed());
      assertEquals(LOGIN_IP_CAPACITY - 1, first.remainingTokens(),
          "remaining after the first consume must be capacity - 1");
      assertEquals(LOGIN_IP_CAPACITY - 2, second.remainingTokens(),
          "remaining must decrement by one per consumed token");
      assertTrue(second.secondsToReset() >= 0, "reset hint must never be negative");
    }

    @Test
    @DisplayName("a blocked snapshot reports zero remaining and is not allowed")
    void blockedSnapshotReportsZeroRemaining() {
      String ip = "203.0.113.40";
      for (int i = 0; i < LOGIN_IP_CAPACITY; i++) {
        limiter.checkLoginByIp(ip);
      }

      RateLimitSnapshot blocked = limiter.checkLoginByIp(ip);

      assertFalse(blocked.allowed(), "past capacity the snapshot must not be allowed");
      assertEquals(0, blocked.remainingTokens(), "a drained bucket reports zero remaining");
    }
  }

  // -----------------------------------------------------------------------------------------------
  // tryLoginByEmail — strict bucket keyed by canonical email
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("tryLoginByEmail() — strict per-account bucket, case-insensitive")
  class TryLoginByEmail {

    @Test
    @DisplayName("allows up to capacity, then blocks the next attempt")
    void allowsUpToCapacityThenBlocks() {
      String email = "alice@example.com";

      for (int i = 1; i <= LOGIN_EMAIL_CAPACITY; i++) {
        assertTrue(limiter.tryLoginByEmail(email), "attempt " + i + " should be allowed");
      }
      assertFalse(limiter.tryLoginByEmail(email), "first attempt past capacity must be rejected");
    }

    @Test
    @DisplayName("different casings / surrounding spaces of the same email share one bucket")
    void emailKeyingUsesCanonicalForm() {
      // Non-canonical keying would let an attacker bypass the limit by toggling case or padding
      // spaces — every variant would mint a fresh bucket.
      assertTrue(limiter.tryLoginByEmail("Alice@Example.com"));
      assertTrue(limiter.tryLoginByEmail(" alice@example.com "));
      assertTrue(limiter.tryLoginByEmail("ALICE@EXAMPLE.COM"));

      assertFalse(limiter.tryLoginByEmail("alice@example.com"),
          "all variants should resolve to the same canonical bucket");
    }
  }

  // -----------------------------------------------------------------------------------------------
  // checkRegisterByIp — very strict bucket
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("checkRegisterByIp() — very strict per-IP bucket")
  class CheckRegisterByIp {

    @Test
    @DisplayName("allows up to capacity, then blocks the next attempt")
    void allowsUpToCapacityThenBlocks() {
      String ip = "203.0.113.10";

      for (int i = 1; i <= REGISTER_IP_CAPACITY; i++) {
        assertTrue(limiter.checkRegisterByIp(ip).allowed(), "attempt " + i + " should be allowed");
      }
      assertFalse(limiter.checkRegisterByIp(ip).allowed(), "first attempt past capacity must be rejected");
    }
  }

  // -----------------------------------------------------------------------------------------------
  // checkRefreshByIp — moderate bucket for the /refresh endpoint
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("checkRefreshByIp() — moderate per-IP bucket")
  class CheckRefreshByIp {

    @Test
    @DisplayName("allows up to capacity, then blocks the next attempt")
    void allowsUpToCapacityThenBlocks() {
      String ip = "203.0.113.10";

      for (int i = 1; i <= REFRESH_IP_CAPACITY; i++) {
        assertTrue(limiter.checkRefreshByIp(ip).allowed(), "attempt " + i + " should be allowed");
      }
      assertFalse(limiter.checkRefreshByIp(ip).allowed(), "first attempt past capacity must be rejected");
    }

    @Test
    @DisplayName("does not consume the login or register buckets")
    void doesNotCrossContaminate() {
      String ip = "203.0.113.10";

      for (int i = 0; i < REFRESH_IP_CAPACITY; i++) {
        limiter.checkRefreshByIp(ip);
      }
      assertFalse(limiter.checkRefreshByIp(ip).allowed(), "refresh bucket should be drained");

      assertTrue(limiter.checkLoginByIp(ip).allowed(), "login bucket must remain untouched");
      assertTrue(limiter.checkRegisterByIp(ip).allowed(), "register bucket must remain untouched");
    }
  }

  // -----------------------------------------------------------------------------------------------
  // checkMfaVerifyByIp — the strictest bucket: a 6-digit TOTP space is the one place online
  // guessing is arithmetically viable, and every caller here already proved the password
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("checkMfaVerifyByIp() — strict per-IP bucket for the step-up endpoint")
  class CheckMfaVerifyByIp {

    @Test
    @DisplayName("allows up to capacity, then blocks with a zero-remaining snapshot")
    void allowsUpToCapacityThenBlocks() {
      String ip = "203.0.113.10";

      for (int i = 1; i <= MFA_IP_CAPACITY; i++) {
        assertTrue(limiter.checkMfaVerifyByIp(ip).allowed(), "attempt " + i + " should be allowed");
      }

      RateLimitSnapshot blocked = limiter.checkMfaVerifyByIp(ip);
      assertFalse(blocked.allowed(), "first attempt past capacity must be rejected");
      assertEquals(0, blocked.remainingTokens(), "a drained bucket reports zero remaining");
    }

    @Test
    @DisplayName("does not consume the login or refresh buckets for the same IP")
    void doesNotCrossContaminate() {
      String ip = "203.0.113.10";

      for (int i = 0; i < MFA_IP_CAPACITY; i++) {
        limiter.checkMfaVerifyByIp(ip);
      }
      assertFalse(limiter.checkMfaVerifyByIp(ip).allowed(), "mfa bucket should be drained");

      assertTrue(limiter.checkLoginByIp(ip).allowed(), "login bucket must remain untouched");
      assertTrue(limiter.checkRefreshByIp(ip).allowed(), "refresh bucket must remain untouched");
    }
  }

  // -----------------------------------------------------------------------------------------------
  // Cross-bucket isolation — exhausting one bucket must not affect the others
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("Bucket isolation across operations")
  class BucketIsolation {

    @Test
    @DisplayName("exhausting register-by-IP does not affect login-by-IP for the same address")
    void registerAndLoginByIpAreIndependent() {
      String ip = "203.0.113.10";

      for (int i = 0; i < REGISTER_IP_CAPACITY; i++) {
        limiter.checkRegisterByIp(ip);
      }
      assertFalse(limiter.checkRegisterByIp(ip).allowed(), "register bucket should be drained");

      assertTrue(limiter.checkLoginByIp(ip).allowed(), "login bucket for the same IP must remain untouched");
    }

    @Test
    @DisplayName("exhausting login-by-email does not affect login-by-IP")
    void loginByEmailAndByIpAreIndependent() {
      String ip = "203.0.113.10";
      String email = "alice@example.com";

      for (int i = 0; i < LOGIN_EMAIL_CAPACITY; i++) {
        limiter.tryLoginByEmail(email);
      }
      assertFalse(limiter.tryLoginByEmail(email), "email bucket should be drained");

      assertTrue(limiter.checkLoginByIp(ip).allowed(), "ip bucket must remain untouched");
    }
  }

  // -----------------------------------------------------------------------------------------------
  // recordSuccessfulLogin — refunds on the email bucket
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("recordSuccessfulLogin() — refunds one token on the email bucket")
  class RecordSuccessfulLogin {

    @Test
    @DisplayName("refund frees exactly one slot for the next attempt")
    void refundsExactlyOneToken() {
      String email = "alice@example.com";

      for (int i = 0; i < LOGIN_EMAIL_CAPACITY; i++) {
        limiter.tryLoginByEmail(email);
      }
      assertFalse(limiter.tryLoginByEmail(email), "bucket should be empty before refund");

      limiter.recordSuccessfulLogin(email);

      assertTrue(limiter.tryLoginByEmail(email),
          "one slot must be available after a single refund");
      assertFalse(limiter.tryLoginByEmail(email),
          "only one token was refunded; the second attempt must be blocked");
    }

    @Test
    @DisplayName("refund matches the bucket key case-insensitively")
    void refundIsCaseInsensitive() {
      for (int i = 0; i < LOGIN_EMAIL_CAPACITY; i++) {
        limiter.tryLoginByEmail("alice@example.com");
      }

      limiter.recordSuccessfulLogin("ALICE@example.COM");

      assertTrue(limiter.tryLoginByEmail("alice@example.com"),
          "refund should hit the same lowercased bucket as the consume");
    }

    @Test
    @DisplayName("is a no-op when no bucket exists for the given email")
    void noOpForUnknownEmail() {
      // Must neither NPE nor materialize a bucket on its own — letting refunds seed buckets
      // would hand an attacker a way to pre-grow the cache.
      assertDoesNotThrow(() -> limiter.recordSuccessfulLogin("never-seen@example.com"));

      for (int i = 1; i <= LOGIN_EMAIL_CAPACITY; i++) {
        assertTrue(limiter.tryLoginByEmail("never-seen@example.com"),
            "attempt " + i + " should be allowed on a fresh bucket");
      }
      assertFalse(limiter.tryLoginByEmail("never-seen@example.com"),
          "bucket should still cap at configured capacity after the prior no-op refund");
    }

    @Test
    @DisplayName("does not exceed capacity when refunded above the bucket maximum")
    void refundDoesNotOvershootCapacity() {
      String email = "alice@example.com";

      // A single consume materializes the bucket (capacity - 1 tokens left).
      assertTrue(limiter.tryLoginByEmail(email));

      // bucket4j clamps refunds at min(current + n, capacity) — a user must not be able to
      // bank tokens from consecutive clean logins.
      for (int i = 0; i < 100; i++) {
        limiter.recordSuccessfulLogin(email);
      }

      for (int i = 1; i <= LOGIN_EMAIL_CAPACITY; i++) {
        assertTrue(limiter.tryLoginByEmail(email),
            "attempt " + i + " after mass refund should still be allowed");
      }
      assertFalse(limiter.tryLoginByEmail(email),
          "bucket must never exceed configured capacity, regardless of refund count");
    }
  }
}
