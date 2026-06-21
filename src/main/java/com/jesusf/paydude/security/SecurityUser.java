package com.jesusf.paydude.security;

import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.UserStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;

/**
 * Adapter that projects a {@link User} entity into Spring Security's {@link UserDetails} contract.
 *
 * <p>Spring Security expects a {@code UserDetails} implementation to expose <b>four boolean
 * checks</b> that the framework evaluates during authentication. Each one models a distinct
 * failure mode and triggers a specific exception, which the API surfaces as a precise HTTP
 * status through the per-concern security advice:
 *
 * <ul>
 *   <li>{@link #isEnabled()} &rarr; account is operationally usable.
 *       Fails with {@code DisabledException} (HTTP 403).</li>
 *   <li>{@link #isAccountNonLocked()} &rarr; account has not been locked (e.g. after N failed logins).
 *       Fails with {@code LockedException} (HTTP 423).</li>
 *   <li>{@link #isAccountNonExpired()} &rarr; the account itself has not reached a hard expiry date.
 *       Fails with {@code AccountExpiredException} (HTTP 401).</li>
 *   <li>{@link #isCredentialsNonExpired()} &rarr; the password is inside the rotation window.
 *       Fails with {@code CredentialsExpiredException} (HTTP 401).</li>
 * </ul>
 *
 * <p>Implementing the full contract (rather than hard-coding {@code true} for the checks we don't
 * care about) lets the API expose the account states that compliance frameworks
 * (SOC 2, PCI-DSS, ISO 27001) expect to see audited. Individual checks can be effectively disabled
 * at the field level:
 *
 * <ul>
 *   <li>{@code accountExpiresAt == null} &rarr; account never expires (the default for retail users).</li>
 *   <li>{@code credentialsExpireAt == null} &rarr; password rotation policy disabled.</li>
 * </ul>
 *
 * <p>This class is a Java {@code record}: immutable, value-based equality, and safe to pass across
 * threads. The same instance is built in two places:
 * <ul>
 *   <li>At login, from the DB {@link User} via {@link #fromEntity(User, int)} in
 *       {@code CustomUserDetailsService}.</li>
 *   <li>On every authenticated request, reconstructed from JWT claims in
 *       {@code JwtAuthenticationFilter} &mdash; no DB round-trip on the hot path. JWT-rebuilt
 *       instances intentionally leave {@code email} blank because access tokens carry no PII.</li>
 * </ul>
 *
 * <p>Trade-off of the stateless rebuild: status changes (e.g. {@code SUSPENDED}, {@code LOCKED})
 * take effect only on the next token issued. Time-based checks (account / credentials expiry) are
 * always evaluated against the current clock, so they do take effect immediately.
 */
public record SecurityUser(
    Long id,
    String email,
    String password,
    UserStatus status,
    Instant accountExpiresAt,
    Instant credentialsExpireAt,
    boolean mfaEnabled,
    Collection<? extends GrantedAuthority> authorities
) implements UserDetails {

  /**
   * Builds a {@code SecurityUser} with the credential rotation policy disabled.
   * Useful for tests and for callers that don't have the policy configuration available.
   */
  public static SecurityUser fromEntity(User user) {
    return fromEntity(user, 0);
  }

  /**
   * Builds a {@code SecurityUser} applying the configured credential rotation policy.
   *
   * @param credentialsExpirationDays number of days before the password expires.
   *                                  {@code 0} disables the policy (credentials never expire).
   */
  public static SecurityUser fromEntity(User user, int credentialsExpirationDays) {
    List<GrantedAuthority> authorities = List.of(
        new SimpleGrantedAuthority(user.getRole().name())
    );

    Instant credentialsExpireAt = null;
    if (credentialsExpirationDays > 0 && user.getPasswordChangedAt() != null) {
      credentialsExpireAt = user.getPasswordChangedAt().plus(credentialsExpirationDays, ChronoUnit.DAYS);
    }

    // mfaEnabled rides on the principal so AuthServiceImpl can branch into the MFA challenge
    // without a second DB read after DaoAuthenticationProvider's single user load. JWT-rebuilt
    // principals hard-code it false: by the time an access token exists, the second factor (when
    // enrolled) was already satisfied — it is login-flow state, not a per-request authority.
    return new SecurityUser(
        user.getId(),
        user.getEmail(),
        user.getPassword(),
        user.getStatus(),
        user.getAccountExpiresAt(),
        credentialsExpireAt,
        user.isMfaEnabled(),
        authorities
    );
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authorities;
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return email;
  }

  /**
   * Returns {@code false} once the account has passed its hard expiry date.
   *
   * <p>A {@code null} {@code accountExpiresAt} means the account never expires &mdash; the default
   * for the vast majority of retail users. The field is set for <b>bounded-access</b> scenarios
   * that are common in the industry:
   *
   * <ul>
   *   <li>Trial or freemium accounts auto-closed after a fixed period.</li>
   *   <li>External contractors or vendors granted temporary back-office access.</li>
   *   <li>Compliance or audit reviewers with a fixed engagement window.</li>
   *   <li>Minor-user accounts scheduled to auto-transition at the age of majority.</li>
   * </ul>
   *
   * <p>On failure Spring Security throws {@code AccountExpiredException}.
   */
  @Override
  public boolean isAccountNonExpired() {
    return accountExpiresAt == null || Instant.now().isBefore(accountExpiresAt);
  }

  /**
   * Returns {@code false} when the account has been administratively locked.
   *
   * <p>Typical triggers in the industry:
   * <ul>
   *   <li>Too many consecutive failed login attempts (anti-bruteforce).</li>
   *   <li>Suspicious activity flagged by a fraud-detection system.</li>
   *   <li>Manual lock by an operator during incident response.</li>
   * </ul>
   *
   * <p>Unlike {@link #isEnabled()} (which covers broader disabled states), a lock is usually
   * <b>recoverable</b> &mdash; either automatically after a cooldown or manually via support.
   *
   * <p>On failure Spring Security throws {@code LockedException}.
   */
  @Override
  public boolean isAccountNonLocked() {
    // Exhaustive switch: any new UserStatus value forces this method to declare its semantics
    // explicitly, instead of silently inheriting "non-locked" from a bare != comparison.
    return switch (status) {
      case LOCKED -> false;
      case ACTIVE, SUSPENDED, CLOSED -> true;
    };
  }

  /**
   * Returns {@code false} when the password has exceeded the configured rotation window.
   *
   * <p>A {@code null} {@code credentialsExpireAt} means no rotation policy is active &mdash; the
   * {@link #fromEntity(User)} default and the posture recommended by <b>NIST SP 800-63B §5.1.1.2</b>
   * (2020+), which explicitly discourages periodic password changes unless a compromise is
   * suspected. Rationale: forced rotation pushes users towards predictable variants
   * ({@code Summer2025!}, {@code Summer2026!}), which weakens rather than strengthens security.
   *
   * <p>Many legacy and regulated environments, however, still mandate rotation:
   * traditional banking, healthcare (HIPAA-adjacent), government, and older PCI-DSS audits.
   * This project exposes the feature so it can be <b>opted in</b> via
   * {@code application.security.credentials-expiration-days} when compliance demands it, and
   * kept off (the default) otherwise.
   *
   * <p>On failure Spring Security throws {@code CredentialsExpiredException}.
   */
  @Override
  public boolean isCredentialsNonExpired() {
    return credentialsExpireAt == null || Instant.now().isBefore(credentialsExpireAt);
  }

  /**
   * Returns {@code true} only for {@link UserStatus#ACTIVE} users.
   *
   * <p>{@code SUSPENDED} and {@code CLOSED} users fall through to this check and are rejected
   * with {@code DisabledException}. {@code LOCKED} is handled separately by
   * {@link #isAccountNonLocked()} so the client receives the more specific
   * {@code LockedException} and the corresponding HTTP 423 response.
   */
  @Override
  public boolean isEnabled() {
    // Same rationale as isAccountNonLocked: a future status (e.g. PENDING_VERIFICATION) must be
    // an explicit decision here, not a default-true or default-false from a bare == check.
    return switch (status) {
      case ACTIVE -> true;
      case LOCKED, SUSPENDED, CLOSED -> false;
    };
  }
}
