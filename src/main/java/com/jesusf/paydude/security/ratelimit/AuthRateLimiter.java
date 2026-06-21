package com.jesusf.paydude.security.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.util.EmailNormalizer;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import org.springframework.stereotype.Service;

/**
 * In-memory token-bucket rate limiter for authentication endpoints.
 *
 * <p>Single-instance deployment by design. When scaling horizontally, swap the local Caffeine
 * caches for a Redis-backed {@code ProxyManager} from {@code bucket4j-redis}; the rest of the API
 * stays unchanged.
 *
 * <p>Per-key {@link Bucket} instances live in {@code Caffeine} caches with
 * {@code expireAfterAccess} matched to the bucket's refill period. Once a key goes silent for one
 * full period, its bucket has refilled to capacity and the entry is safe to evict — keeping it
 * around would only consume memory. A plain {@code ConcurrentHashMap} retains one entry per
 * unique IP and email forever, which an attacker can weaponize as an unbounded memory leak by
 * spraying random values. {@code maximumSize} on each cache caps the worst case during sustained
 * pressure before eviction catches up.
 *
 * <p>Threshold rationale (configurable via {@code application.security.rate-limit.*}):
 * <ul>
 *   <li><b>Login by IP</b>: generous (NAT/corporate-proxy traffic shares IPs). Stops brute-force
 *       from a single origin without false-positives on legitimate shared IPs.</li>
 *   <li><b>Login by email</b>: strict. No legitimate human exceeds 5 failed logins in 15 minutes
 *       before resetting their password. Counts <i>failures only</i>, so successful logins on
 *       multiple devices do not consume the bucket.</li>
 *   <li><b>Register by IP</b>: very strict. There is no legitimate flow where one origin needs
 *       to create multiple accounts in a short window.</li>
 * </ul>
 *
 * <p>Defaults live in {@code application-dev.properties} and {@code application-prod.properties}.
 * Operators may tighten or loosen the buckets per environment without a redeploy — the values
 * are bound via {@link SecurityProperties.RateLimit}, validated at boot, and exposed through
 * {@code /actuator/configprops}.
 */
@Service
public class AuthRateLimiter {

  private final Bandwidth loginByIpBandwidth;
  private final Bandwidth loginByEmailBandwidth;
  private final Bandwidth registerByIpBandwidth;
  private final Bandwidth refreshByIpBandwidth;
  private final Bandwidth mfaByIpBandwidth;

  private final Cache<String, Bucket> loginIpBuckets;
  private final Cache<String, Bucket> loginEmailBuckets;
  private final Cache<String, Bucket> registerIpBuckets;
  private final Cache<String, Bucket> refreshIpBuckets;
  private final Cache<String, Bucket> mfaIpBuckets;

  // Retained per-IP bucket config (capacity + period) so checkXxxByIp can report the quota (q) and
  // window (w) for the RateLimit-Policy header — keeping SecurityProperties out of the filter, which
  // is component-scanned into every @WebMvcTest slice and must stay dependency-light.
  private final SecurityProperties.RateLimit.Bucket loginByIpConfig;
  private final SecurityProperties.RateLimit.Bucket registerByIpConfig;
  private final SecurityProperties.RateLimit.Bucket refreshByIpConfig;
  private final SecurityProperties.RateLimit.Bucket mfaByIpConfig;

  public AuthRateLimiter(SecurityProperties securityProperties) {
    SecurityProperties.RateLimit limits = securityProperties.rateLimit();
    this.loginByIpBandwidth = RateLimitBuckets.toBandwidth(limits.loginByIp());
    this.loginByEmailBandwidth = RateLimitBuckets.toBandwidth(limits.loginByEmail());
    this.registerByIpBandwidth = RateLimitBuckets.toBandwidth(limits.registerByIp());
    this.refreshByIpBandwidth = RateLimitBuckets.toBandwidth(limits.refreshByIp());
    this.mfaByIpBandwidth = RateLimitBuckets.toBandwidth(limits.mfaByIp());

    this.loginIpBuckets = RateLimitBuckets.buildCache(limits.loginByIp().period());
    this.loginEmailBuckets = RateLimitBuckets.buildCache(limits.loginByEmail().period());
    this.registerIpBuckets = RateLimitBuckets.buildCache(limits.registerByIp().period());
    this.refreshIpBuckets = RateLimitBuckets.buildCache(limits.refreshByIp().period());
    this.mfaIpBuckets = RateLimitBuckets.buildCache(limits.mfaByIp().period());

    this.loginByIpConfig = limits.loginByIp();
    this.registerByIpConfig = limits.registerByIp();
    this.refreshByIpConfig = limits.refreshByIp();
    this.mfaByIpConfig = limits.mfaByIp();
  }

  /**
   * Consumes one token from the per-IP login bucket and reports the outcome (allowed flag,
   * remaining tokens, seconds to reset) so the caller can emit the {@code RateLimit} header.
   *
   * @param ip the client IP
   * @return a snapshot of the consumption attempt
   */
  public RateLimitSnapshot checkLoginByIp(String ip) {
    return toSnapshot(loginByIpConfig, loginIpBuckets
        .get(ip, k -> Bucket.builder().addLimit(loginByIpBandwidth).build())
        .tryConsumeAndReturnRemaining(1));
  }

  /**
   * Consumes one token from the per-email login bucket. The email is lower-cased so the bucket
   * is case-insensitive. A successful login refunds the token via {@link #recordSuccessfulLogin}.
   *
   * @param email the login email
   * @return {@code true} if the request is within the limit, {@code false} if throttled
   */
  public boolean tryLoginByEmail(String email) {
    return loginEmailBuckets
        .get(EmailNormalizer.normalize(email), k -> Bucket.builder().addLimit(loginByEmailBandwidth).build())
        .tryConsume(1);
  }

  /**
   * Consumes one token from the per-IP registration bucket and reports the outcome for the
   * {@code RateLimit} header.
   *
   * @param ip the client IP
   * @return a snapshot of the consumption attempt
   */
  public RateLimitSnapshot checkRegisterByIp(String ip) {
    return toSnapshot(registerByIpConfig, registerIpBuckets
        .get(ip, k -> Bucket.builder().addLimit(registerByIpBandwidth).build())
        .tryConsumeAndReturnRemaining(1));
  }

  /**
   * Consumes one token from the per-IP refresh-token bucket and reports the outcome for the
   * {@code RateLimit} header.
   *
   * @param ip the client IP
   * @return a snapshot of the consumption attempt
   */
  public RateLimitSnapshot checkRefreshByIp(String ip) {
    return toSnapshot(refreshByIpConfig, refreshIpBuckets
        .get(ip, k -> Bucket.builder().addLimit(refreshByIpBandwidth).build())
        .tryConsumeAndReturnRemaining(1));
  }

  /**
   * Consumes one token from the per-IP MFA-verify bucket and reports the outcome for the
   * {@code RateLimit} header. Strictest of the IP buckets: a 6-digit TOTP space is the one place
   * in the auth surface where online guessing is arithmetically viable, and every caller here has
   * already proven the password.
   *
   * @param ip the client IP
   * @return a snapshot of the consumption attempt
   */
  public RateLimitSnapshot checkMfaVerifyByIp(String ip) {
    return toSnapshot(mfaByIpConfig, mfaIpBuckets
        .get(ip, k -> Bucket.builder().addLimit(mfaByIpBandwidth).build())
        .tryConsumeAndReturnRemaining(1));
  }

  /**
   * Refunds a token to the email bucket on successful login. Without this, a user who
   * mistypes their password 4 times and then succeeds would still see their bucket near
   * exhaustion for the next 15 minutes — false positives on subsequent legitimate logins.
   *
   * <p>Uses {@code getIfPresent} (not {@code get}) on purpose: if Caffeine already evicted
   * the entry — meaning the bucket would have refilled to full capacity anyway — there is
   * nothing to refund, and we avoid materializing a fresh empty-of-debt bucket for nothing.
   */
  public void recordSuccessfulLogin(String email) {
    Bucket bucket = loginEmailBuckets.getIfPresent(EmailNormalizer.normalize(email));
    if (bucket != null) {
      bucket.addTokens(1);
    }
  }

  /**
   * Projects a bucket4j {@link ConsumptionProbe} into the framework-agnostic {@link RateLimitSnapshot}.
   * {@code getNanosToWaitForReset()} is the time until the bucket is back at full capacity — the
   * window-reset semantics the {@code RateLimit} header's {@code t} parameter expects — rounded up
   * to whole seconds. Remaining and reset are clamped to non-negative for the structured-field output.
   */
  private static RateLimitSnapshot toSnapshot(SecurityProperties.RateLimit.Bucket config, ConsumptionProbe probe) {
    long secondsToReset = Math.ceilDiv(probe.getNanosToWaitForReset(), 1_000_000_000L);
    return new RateLimitSnapshot(
        probe.isConsumed(),
        config.capacity(),
        config.period().toSeconds(),
        Math.max(probe.getRemainingTokens(), 0),
        Math.max(secondsToReset, 0)
    );
  }
}
