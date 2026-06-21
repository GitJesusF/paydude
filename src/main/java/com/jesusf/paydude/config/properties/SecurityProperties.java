package com.jesusf.paydude.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Type-safe binding for every {@code application.security.*} property.
 *
 * <p>Replaces what used to be scattered {@code @Value} injections and {@code private static final}
 * constants. Three concrete benefits over the previous approach:
 *
 * <ul>
 *   <li><b>Single source of truth.</b> {@code credentials-expiration-days} used to be injected
 *       independently in {@code CustomUserDetailsService} and {@code AuthServiceImpl}; if one
 *       had drifted, the rotation window enforced on login would have differed from the one
 *       embedded in the JWT, producing silently inconsistent expirations across requests.</li>
 *   <li><b>Validation at boot.</b> {@code @Validated} + the bean-validation annotations on each
 *       component (e.g. {@code @NotBlank}, {@code @Positive}) make the application fail fast at
 *       startup if a property is missing or malformed, instead of surfacing later as a
 *       {@code NullPointerException} or a malformed JWT at the first login attempt.</li>
 *   <li><b>Observability.</b> Spring Boot's {@code /actuator/configprops} endpoint exposes every
 *       bound property along with its origin (which {@code application-*.properties} file or
 *       environment variable supplied the value), so an operator can verify the live config
 *       without restarting or grepping the codebase.</li>
 * </ul>
 *
 * @param jwt                         JWT signing and lifetime configuration
 * @param credentialsExpirationDays   Days a password remains valid before forcing rotation;
 *                                    {@code 0} disables the policy (NIST SP 800-63B default)
 * @param rateLimit                   Token-bucket thresholds enforced by {@code AuthRateLimiter}
 * @param refreshToken                Refresh-token lifetime and policy
 * @param password                    Compromised-password screening policy
 * @param actuator                    Credentials for the HTTP Basic scraper/operator on Actuator
 * @param lockout                     Anti-bruteforce account-lockout thresholds enforced by
 *                                    {@code LoginAttemptService}
 * @param audit                       Security audit-log policy (toggle + retention) consumed by
 *                                    {@code SecurityAuditService}
 * @param mfa                         TOTP second-factor policy (challenge lifetime, otpauth issuer)
 *                                    consumed by {@code JwtService} and {@code MfaService}
 */
@ConfigurationProperties(prefix = "application.security")
@Validated
public record SecurityProperties(
    @NotNull @Valid Jwt jwt,
    @PositiveOrZero int credentialsExpirationDays,
    @NotNull @Valid RateLimit rateLimit,
    @NotNull @Valid RefreshToken refreshToken,
    @NotNull @Valid Password password,
    @NotNull @Valid Actuator actuator,
    @NotNull @Valid Lockout lockout,
    @NotNull @Valid Audit audit,
    @NotNull @Valid Mfa mfa
) {

  /**
   * @param secretKey   Base64-encoded HMAC key for signing tokens. Must come from the environment
   *                    in production; the dev profile bakes a stable test key for convenience.
   * @param expiration  Token lifetime in milliseconds. Exposed in seconds via
   *                    {@code JwtService.getExpirationSeconds()} for the OAuth-style
   *                    {@code expires_in} field.
   */
  public record Jwt(
      @NotBlank String secretKey,
      @Positive long expiration
  ) {}

  /**
   * Rate-limit thresholds consumed by {@code AuthRateLimiter}. Externalised so operators can
   * tighten or loosen the buckets per environment (or in response to a live incident such as a
   * credential-stuffing wave) without recompiling. The previous implementation hard-coded these
   * as {@code private static final Bandwidth} constants — a redeploy was required for any
   * adjustment, which is unacceptable for an operational lever of this kind.
   *
   * @param loginByIp        Throttle for {@code POST /auth/login} keyed by client IP — generous,
   *                         because NAT and corporate proxies share IPs.
   * @param loginByEmail     Throttle for {@code POST /auth/login} keyed by email — strict;
   *                         counts failures only, successful logins refund a token.
   * @param registerByIp     Throttle for {@code POST /auth/register} keyed by client IP — very
   *                         strict; no legitimate origin creates many accounts in a short window.
   * @param refreshByIp      Throttle for {@code POST /auth/refresh} keyed by client IP — moderate;
   *                         legitimate clients refresh roughly once per access-token lifetime, so
   *                         a tight bucket suffices and stops token-enumeration attempts.
   * @param writeByUser      Throttle for the money-moving writes (deposit, withdraw, transfer)
   *                         keyed by the authenticated user id — consumed by {@code WriteRateLimiter}
   *                         from the account/transaction controllers. These endpoints sit behind a
   *                         bearer token, so the meaningful abuse key is the principal, not the IP:
   *                         a single authenticated account replaying writes is what grows DB state
   *                         (idempotency rows, transactions, audits) and hammers account lookups.
   * @param mfaByIp          Throttle for {@code POST /auth/mfa/verify} keyed by client IP — strict;
   *                         a 6-digit TOTP has only 10^6 values (≈3 valid per attempt inside the
   *                         ±1-step window), so the verify endpoint is the one auth surface where
   *                         online guessing is arithmetically viable. Backed up per-account by the
   *                         persistent lockout, which counts failed codes like failed passwords.
   * @param reauthByUser     Throttle for the password-re-authentication gates on the authenticated
   *                         account-security endpoints — change-password, MFA setup, MFA disable —
   *                         keyed by the authenticated user id and enforced by
   *                         {@code ReauthRateLimiter} from the controllers. These verify the account
   *                         password behind a bearer token but, unlike {@code /auth/login}, do not
   *                         feed the per-IP/per-email auth throttles, so without this tier a stolen
   *                         token could brute-force the password at BCrypt speed unbounded. As
   *                         sensitive and low-frequency as a login, so it mirrors {@code loginByEmail}
   *                         (e.g. 5 / 15m); a throttle (429) rather than the account lockout keeps the
   *                         legitimate owner able to log in and evict the attacker.
   */
  public record RateLimit(
      @NotNull @Valid Bucket loginByIp,
      @NotNull @Valid Bucket loginByEmail,
      @NotNull @Valid Bucket registerByIp,
      @NotNull @Valid Bucket refreshByIp,
      @NotNull @Valid Bucket writeByUser,
      @NotNull @Valid Bucket mfaByIp,
      @NotNull @Valid Bucket reauthByUser
  ) {

    /**
     * A single token-bucket definition. {@code capacity} is both the bucket size and the refill
     * amount per {@code period} (i.e. {@code refillIntervally(capacity, period)}). Spring Boot
     * parses {@link Duration} from ISO-8601 ({@code "PT15M"}) or a friendlier format
     * ({@code "15m"}, {@code "1h"}) — see {@code spring.boot.convert.DurationStyle}.
     *
     * @param capacity Maximum tokens the bucket holds and the count refilled each {@code period}
     * @param period   Refill window
     */
    public record Bucket(
        @Positive int capacity,
        @NotNull Duration period
    ) {}
  }

  /**
   * Refresh-token policy. Externalised so operators can tighten the lifetime per environment
   * (e.g. shorter in regulated tenants) without recompiling.
   *
   * <p>{@code @DurationMin} enforces a minimum at boot — a sub-minute refresh token would
   * provide no operational benefit and almost certainly indicates a misconfigured property
   * (e.g. someone wrote {@code 168} expecting hours but Boot read it as ms).
   *
   * @param expiration Refresh-token lifetime. Must be ≥ the access-token lifetime, otherwise the
   *                   client would need to re-login to obtain a fresh refresh; that invariant is
   *                   not enforced declaratively (it would require cross-field validation) but
   *                   is documented in {@code application-*.properties}.
   */
  public record RefreshToken(
      @NotNull @DurationMin(seconds = 60) Duration expiration
  ) {}

  /**
   * Compromised-password screening policy.
   *
   * <p>When enabled, a chosen password is checked against the HaveIBeenPwned breach corpus at
   * registration and at rotation, implementing NIST SP 800-63B §5.1.1.2 ("verifiers SHALL compare
   * the prospective secret against a list of known compromised values"). The check uses
   * k-anonymity — only the first five hex characters of the password's SHA-1 digest ever leave
   * the JVM, never the password itself.
   *
   * <p>Externalised as a toggle so the {@code test} profile can disable it and keep integration
   * tests off the public network. Unit tests mock the checker outright and are unaffected either
   * way. Defaults to {@code true} via {@code application.properties}; an offline environment is
   * still safe because the screening fails open (a HaveIBeenPwned outage skips the check rather
   * than blocking the user).
   *
   * @param breachCheckEnabled {@code true} wires the live
   *                           {@code HaveIBeenPwnedRestApiPasswordChecker}; {@code false} swaps in
   *                           a no-op checker that treats every password as not-compromised
   */
  public record Password(boolean breachCheckEnabled) {}

  /**
   * Credentials for the HTTP Basic principal that guards the admin tier of Actuator
   * (everything except {@code health}/{@code info} — most notably {@code /actuator/prometheus}).
   *
   * <p>This is a dedicated <b>technical account</b>, deliberately decoupled from the application
   * {@code users} table: a metrics scraper or an on-call operator is a machine/role, not a banking
   * customer, so it has no business carrying a row in the domain user store, a BCrypt login hash,
   * or a refresh-token family. {@code SecurityConfig} loads these two values into an in-memory
   * {@code UserDetails} scoped to the Actuator filter chain only — the JWT chain that protects
   * {@code /v1/**} never sees them, and this principal can never authenticate against the API.
   *
   * <p>The {@code password} must come from the environment in production (the prod overlay makes
   * {@code ACTUATOR_PASSWORD} fail-fast); the dev profile bakes a convenience default so a fresh
   * clone's local observability stack scrapes without setup.
   *
   * @param username Basic-auth username the scraper presents (e.g. {@code prometheus})
   * @param password Basic-auth password; injected via {@code ACTUATOR_PASSWORD} in real deploys
   */
  public record Actuator(
      @NotBlank String username,
      @NotBlank String password
  ) {}

  /**
   * Anti-bruteforce account-lockout policy, enforced by {@code LoginAttemptService}. This is the
   * <b>persistent</b> second line behind {@code AuthRateLimiter}'s in-memory per-email bucket: it
   * survives restarts, keys on the account itself, and transitions the user to
   * {@code UserStatus.LOCKED} (HTTP 423) once the threshold is reached.
   *
   * <p>The lock is deliberately <b>temporary</b> ({@code lockoutDuration} then auto-release), not
   * permanent: a permanent "contact support" lock would let anyone who knows a victim's email lock
   * them out at will — a denial-of-service vector. OWASP ASVS V2.2 and NIST SP 800-63B §5.2.2 both
   * favour throttling / temporary lockout.
   *
   * <p>Externalised as a toggle so a profile (or an operator, via {@code ACCOUNT_LOCKOUT_ENABLED})
   * can disable it; when {@code false}, {@code LoginAttemptService} short-circuits and the login
   * path keeps its single-DB-read profile.
   *
   * @param enabled         whether lockout is active; {@code false} makes every operation a no-op
   * @param maxAttempts     consecutive failed logins that trigger a lock (e.g. {@code 5})
   * @param lockoutDuration how long a triggered lock lasts before it auto-releases (e.g. {@code 15m})
   */
  public record Lockout(
      boolean enabled,
      @Positive int maxAttempts,
      @NotNull @DurationMin(seconds = 1) Duration lockoutDuration
  ) {}

  /**
   * Security audit-log policy, consumed by {@code SecurityAuditService}. The audit log is the
   * append-only detection/forensics trail (OWASP ASVS V7) that complements the prevention controls
   * (rate limiting, lockout, breach screening, token rotation): it records login success/failure,
   * logout, registration, password change, account lockout and refresh-token reuse into
   * {@code security_audit_events}.
   *
   * <p>{@code enabled} is a kill-switch — when {@code false}, {@code SecurityAuditService.record}
   * short-circuits and writes nothing. Recording is fail-safe regardless (a failed insert never
   * disrupts the audited operation), so the toggle exists for parity with the other security levers,
   * not because the path is risky; a real deployment should leave it on — you cannot investigate what
   * you never recorded.
   *
   * <p>{@code retention} bounds table growth: {@code ExpiredDataCleanupJob} purges rows older than
   * {@code now − retention}. {@code @DurationMin} rejects a sub-minute value at boot as an obvious
   * misconfiguration (e.g. {@code 365} mistakenly read as milliseconds rather than days).
   *
   * @param enabled   whether events are recorded; {@code false} makes recording a no-op
   * @param retention how long an audit row is kept before the scheduled purge removes it
   */
  public record Audit(
      boolean enabled,
      @NotNull @DurationMin(seconds = 60) Duration retention
  ) {}

  /**
   * TOTP second-factor policy (RFC 6238), consumed by {@code JwtService} (challenge-token
   * lifetime) and {@code MfaService} (provisioning-URI issuer). MFA itself is per-user opt-in —
   * there is no global on/off switch here, because a kill-switch that silently downgrades enrolled
   * users to single-factor would be a security regression an operator could trip by accident.
   *
   * <p>{@code challengeExpiration} bounds the window between a correct password and the TOTP
   * submission. Five minutes is generous for a human reaching for a phone yet short enough that an
   * intercepted challenge token is near-worthless — it grants nothing but the right to attempt a
   * code, on an endpoint that is IP-throttled and lockout-protected. {@code @DurationMin} rejects
   * a sub-30s window (one TOTP step) as an obvious misconfiguration.
   *
   * @param challengeExpiration how long the one-shot MFA challenge token stays redeemable
   * @param issuer              the service label authenticator apps display, embedded in the
   *                            {@code otpauth://} provisioning URI
   */
  public record Mfa(
      @NotNull @DurationMin(seconds = 30) Duration challengeExpiration,
      @NotBlank String issuer
  ) {}
}