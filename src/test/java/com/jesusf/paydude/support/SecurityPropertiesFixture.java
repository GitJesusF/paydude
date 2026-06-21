package com.jesusf.paydude.support;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.config.properties.SecurityProperties.Actuator;
import com.jesusf.paydude.config.properties.SecurityProperties.Audit;
import com.jesusf.paydude.config.properties.SecurityProperties.Jwt;
import com.jesusf.paydude.config.properties.SecurityProperties.Lockout;
import com.jesusf.paydude.config.properties.SecurityProperties.Mfa;
import com.jesusf.paydude.config.properties.SecurityProperties.Password;
import com.jesusf.paydude.config.properties.SecurityProperties.RateLimit;
import com.jesusf.paydude.config.properties.SecurityProperties.RateLimit.Bucket;
import com.jesusf.paydude.config.properties.SecurityProperties.RefreshToken;

import java.time.Duration;

/**
 * Unit-test fixture for {@link SecurityProperties}.
 *
 * <p>Several unit tests need a valid {@code SecurityProperties} instance whose subgraphs they do not
 * actually exercise — they need the record to <i>exist</i> so the service-under-test's constructor
 * resolves, but the values inside the unused subgraphs are placeholders. Without this helper, each
 * test had to construct {@code Jwt + RateLimit(b,b,b,b,b) + RefreshToken + ...} by hand. Every time
 * the record grows a new field (a new bucket, a new policy), all the {@code setUp()} blocks had to be
 * patched in lockstep — the recurring source of "tests broke because the record gained a field"
 * friction. Centralising construction here means a new field is absorbed in one place.
 *
 * <p>The integration tests do not go through this helper. They bind {@code SecurityProperties}
 * from {@code application-test.properties} via {@code @ActiveProfiles("test")}, exercising the
 * real {@code @ConfigurationProperties} binding path. Whether the values in this fixture match
 * the values in that file is intentionally irrelevant: unit tests mock everything that <i>reads</i>
 * the properties, so the numbers here are filler that must only satisfy Jakarta validation.
 *
 * <p>Use the named factories instead of the raw record constructor in any new unit test that needs
 * a {@code SecurityProperties}.
 */
public final class SecurityPropertiesFixture {

  /**
   * Stable Base64-encoded HS256 key. Decoded value is irrelevant; what matters is that the
   * decoded length (≥ 32 bytes) satisfies {@code Keys.hmacShaKeyFor()} when {@code JwtService}
   * initialises. Tests that exercise the real signing pipeline (e.g. {@link
   * com.jesusf.paydude.security.JwtServiceTest}) verify the round-trip with this same key, so
   * making it stable removes one source of inter-test divergence.
   */
  public static final String STABLE_SECRET_KEY = "dGVzdC1zZWNyZXQta2V5LWZvci11bml0LXRlc3RzLW9ubHk=";

  private static final Jwt DEFAULT_JWT = new Jwt(STABLE_SECRET_KEY, 3_600_000L);
  private static final Bucket DEFAULT_BUCKET = new Bucket(20, Duration.ofMinutes(1));
  private static final RateLimit DEFAULT_RATE_LIMIT =
      new RateLimit(DEFAULT_BUCKET, DEFAULT_BUCKET, DEFAULT_BUCKET, DEFAULT_BUCKET, DEFAULT_BUCKET,
          DEFAULT_BUCKET, DEFAULT_BUCKET);
  private static final RefreshToken DEFAULT_REFRESH = new RefreshToken(Duration.ofDays(7));
  // Breach screening off in unit tests: the services that read this are tested with a mocked
  // BreachedPasswordGuard, so the live HaveIBeenPwned checker is never wired here. Off keeps the
  // intent explicit — no unit test should ever depend on the public network.
  private static final Password DEFAULT_PASSWORD = new Password(false);
  // Actuator Basic-auth scraper credential. Placeholder only — no unit test that uses this fixture
  // authenticates against the actuator filter chain; the values just satisfy @NotBlank validation.
  private static final Actuator DEFAULT_ACTUATOR = new Actuator("prometheus", "unit-test-secret");
  // Account-lockout policy. Placeholder for tests that do not exercise lockout (the only reader is
  // LoginAttemptServiceImpl, which the consumers of this fixture mock away). LoginAttemptServiceImplTest
  // builds its own Lockout via withLockout(...) instead of relying on these numbers.
  private static final Lockout DEFAULT_LOCKOUT = new Lockout(true, 5, Duration.ofMinutes(15));
  // Security audit-log policy. Enabled with a long retention; the only reader is SecurityAuditService,
  // which consumers of this fixture mock away. SecurityAuditServiceImplTest builds its own Audit via
  // withAudit(...) to exercise the enabled/disabled branches.
  private static final Audit DEFAULT_AUDIT = new Audit(true, Duration.ofDays(365));
  // TOTP second-factor policy. The 5-minute challenge window matches the cross-profile default;
  // JwtServiceTest exercises the challenge mint/parse round-trip against it, everything else just
  // needs the record present for SecurityProperties to validate.
  private static final Mfa DEFAULT_MFA = new Mfa(Duration.ofMinutes(5), "PayDude");

  private SecurityPropertiesFixture() {}

  /**
   * Default placeholders that satisfy every record validation. Credential-rotation policy is
   * disabled ({@code 0}); rate-limit buckets are generous (20/min); refresh-token TTL is 7 days;
   * lockout after 5 attempts for 15 minutes; audit logging enabled with 365-day retention. Use this
   * in any unit test that does not need to override any subgraph.
   */
  public static SecurityProperties defaults() {
    return new SecurityProperties(
        DEFAULT_JWT, 0, DEFAULT_RATE_LIMIT, DEFAULT_REFRESH, DEFAULT_PASSWORD, DEFAULT_ACTUATOR, DEFAULT_LOCKOUT,
        DEFAULT_AUDIT, DEFAULT_MFA);
  }

  /**
   * Same as {@link #defaults()} but with a non-zero credentials-expiration window. Used by
   * {@code CustomUserDetailsServiceTest} to exercise both the off (0) and on (90) branches of
   * the rotation policy.
   */
  public static SecurityProperties withCredentialsExpiration(int days) {
    return new SecurityProperties(
        DEFAULT_JWT, days, DEFAULT_RATE_LIMIT, DEFAULT_REFRESH, DEFAULT_PASSWORD, DEFAULT_ACTUATOR, DEFAULT_LOCKOUT,
        DEFAULT_AUDIT, DEFAULT_MFA);
  }

  /**
   * Same as {@link #defaults()} but overrides the JWT lifetime. Used by {@code JwtServiceTest}
   * to verify {@code getExpirationSeconds()} across multiple TTLs.
   */
  public static SecurityProperties withJwtExpiration(long expirationMillis) {
    return new SecurityProperties(
        new Jwt(STABLE_SECRET_KEY, expirationMillis), 0, DEFAULT_RATE_LIMIT, DEFAULT_REFRESH, DEFAULT_PASSWORD,
        DEFAULT_ACTUATOR, DEFAULT_LOCKOUT, DEFAULT_AUDIT, DEFAULT_MFA
    );
  }

  /**
   * Same as {@link #defaults()} but overrides the JWT signing secret. Used by
   * {@code JwtServiceTest} to pin startup-time validation of malformed or weak HMAC keys.
   */
  public static SecurityProperties withJwtSecretKey(String secretKey) {
    return new SecurityProperties(
        new Jwt(secretKey, 3_600_000L), 0, DEFAULT_RATE_LIMIT, DEFAULT_REFRESH, DEFAULT_PASSWORD,
        DEFAULT_ACTUATOR, DEFAULT_LOCKOUT, DEFAULT_AUDIT, DEFAULT_MFA
    );
  }

  /**
   * Same as {@link #defaults()} but overrides the rate-limit subgraph. Used by
   * {@code AuthRateLimiterTest}, where the test's whole point is to exercise specific bucket
   * capacities.
   */
  public static SecurityProperties withRateLimit(RateLimit rateLimit) {
    return new SecurityProperties(
        DEFAULT_JWT, 0, rateLimit, DEFAULT_REFRESH, DEFAULT_PASSWORD, DEFAULT_ACTUATOR, DEFAULT_LOCKOUT,
        DEFAULT_AUDIT, DEFAULT_MFA);
  }

  /**
   * Same as {@link #defaults()} but overrides the lockout subgraph. Used by
   * {@code LoginAttemptServiceImplTest} to exercise a known threshold/window and the enabled/disabled
   * branches.
   */
  public static SecurityProperties withLockout(Lockout lockout) {
    return new SecurityProperties(
        DEFAULT_JWT, 0, DEFAULT_RATE_LIMIT, DEFAULT_REFRESH, DEFAULT_PASSWORD, DEFAULT_ACTUATOR, lockout,
        DEFAULT_AUDIT, DEFAULT_MFA);
  }

  /**
   * Same as {@link #defaults()} but overrides the audit subgraph. Used by
   * {@code SecurityAuditServiceImplTest} to exercise the enabled/disabled branches and a known
   * retention window.
   */
  public static SecurityProperties withAudit(Audit audit) {
    return new SecurityProperties(
        DEFAULT_JWT, 0, DEFAULT_RATE_LIMIT, DEFAULT_REFRESH, DEFAULT_PASSWORD, DEFAULT_ACTUATOR, DEFAULT_LOCKOUT,
        audit, DEFAULT_MFA);
  }
}
