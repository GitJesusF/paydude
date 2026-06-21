package com.jesusf.paydude.entity;

import com.jesusf.paydude.enums.Role;
import com.jesusf.paydude.enums.UserStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
@EntityListeners(AuditingEntityListener.class)
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(updatable = false)
  private Long id;

  @Column(name = "first_name", length = 50, nullable = false)
  private String firstName;

  @Column(name = "last_name", length = 50, nullable = false)
  private String lastName;

  @EqualsAndHashCode.Include
  @Column(name = "email", length = 100, nullable = false, unique = true)
  private String email;

  @Column(name = "password", length = 255, nullable = false)
  private String password;

  @Enumerated(EnumType.STRING)
  @Column(name = "role", length = 20, nullable = false)
  private Role role;

  @Builder.Default
  @Enumerated(EnumType.STRING)
  @Column(name = "status", length = 20, nullable = false)
  private UserStatus status = UserStatus.ACTIVE;

  /**
   * Timestamp of the last password change. Backs the credential rotation policy.
   *
   * <p>Set on registration and updated on every password change. Never {@code null} &mdash; a row
   * without a known change date is treated as "changed at creation time".
   *
   * <p>Combined with {@code application.security.credentials-expiration-days}, this field feeds
   * {@code SecurityUser.credentialsExpireAt} and the matching JWT claim. The check runs both at
   * login (via {@code SecurityUser.isCredentialsNonExpired()}) and on every authenticated request
   * (via {@code JwtAuthenticationFilter}).
   *
   * <p><b>Compliance context.</b> Periodic forced password rotation is explicitly discouraged by
   * <b>NIST SP 800-63B §5.1.1.2</b> (2020+) unless a compromise is suspected, because it leads
   * users to pick predictable variants. It is, however, still mandatory in many PCI-DSS v3
   * audits, traditional banking platforms and legacy healthcare systems. This project keeps the
   * policy <b>disabled by default</b> (config value {@code 0}) and exposes it as an opt-in
   * feature for environments that need it.
   */
  @Column(name = "password_changed_at", nullable = false)
  private Instant passwordChangedAt;

  /**
   * Optional hard expiry date for this account. {@code null} means the account never expires.
   *
   * <p>When set, logins are rejected once the instant is passed, regardless of {@link #status}.
   * The check is enforced both at login and on every authenticated request, so revoking access
   * is as simple as setting this field in the DB.
   *
   * <p>Typical industry use cases:
   * <ul>
   *   <li>Trial or freemium accounts bounded by SLA.</li>
   *   <li>Contractor and vendor accounts with a contractual end date.</li>
   *   <li>External auditors or regulators with a time-boxed engagement.</li>
   *   <li>Minor-user accounts scheduled to auto-transition at the age of majority.</li>
   * </ul>
   */
  @Column(name = "account_expires_at")
  private Instant accountExpiresAt;

  /**
   * Count of <b>consecutive</b> failed login attempts since the last successful login. Reset to
   * {@code 0} on the next successful authentication.
   *
   * <p>Backs the anti-bruteforce lockout (OWASP ASVS V2.2 / NIST SP 800-63B §5.2.2): once this
   * reaches {@code application.security.lockout.max-attempts}, the login flow flips {@link #status}
   * to {@link com.jesusf.paydude.enums.UserStatus#LOCKED} and stamps {@link #lockoutExpiresAt}.
   * Mutated only through atomic UPDATEs in {@code LoginAttemptService}, never by dirty checking.
   */
  @Builder.Default
  @Column(name = "failed_login_attempts", nullable = false)
  private int failedLoginAttempts = 0;

  /**
   * Instant at which a <b>temporary</b> lock auto-releases. Interpretation depends on {@link #status}:
   *
   * <ul>
   *   <li>{@code status != LOCKED} &rarr; not locked; value is irrelevant (kept {@code null}).</li>
   *   <li>{@code status == LOCKED} &amp; {@code null} &rarr; a permanent/administrative lock that
   *       never auto-releases (manual unlock only).</li>
   *   <li>{@code status == LOCKED} &amp; non-null &rarr; a temporary anti-bruteforce lock; the login
   *       flow releases it once {@code now >= lockoutExpiresAt}.</li>
   * </ul>
   */
  @Column(name = "lockout_expires_at")
  private Instant lockoutExpiresAt;

  /**
   * Whether the TOTP second factor is active for this account. While {@code true}, a correct
   * password at login yields an MFA challenge instead of tokens; the session is only minted after
   * {@code POST /v1/auth/mfa/verify} proves possession of the enrolled authenticator (or a
   * recovery code). Flipped on by {@code /v1/users/me/mfa/confirm}, off by {@code .../disable}.
   */
  @Builder.Default
  @Column(name = "mfa_enabled", nullable = false)
  private boolean mfaEnabled = false;

  /**
   * Base32-encoded TOTP shared secret (RFC 6238), {@code null} when MFA was never set up.
   * Non-null with {@code mfaEnabled == false} marks a <b>pending</b> enrollment: {@code /setup}
   * generated the secret but {@code /confirm} has not yet proved the authenticator works.
   *
   * <p>Stored as it must be used: the verifier recomputes the HMAC from the raw secret on every
   * check, so unlike a password this value cannot be hashed (see V0_004 / patterns #24 for the
   * encryption-at-rest trade-off).
   */
  @Column(name = "mfa_secret", length = 64)
  private String mfaSecret;

  /**
   * Last TOTP time step that verified successfully — the RFC 6238 §5.2 replay guard. A submitted
   * code is only accepted when its matching step is strictly greater, enforced by an atomic
   * UPDATE in {@code UserRepository.markMfaStepUsed} so two concurrent submissions of the same
   * code cannot both win.
   */
  @Column(name = "mfa_last_used_step")
  private Long mfaLastUsedStep;

  @CreatedDate
  @Column(name = "created_at")
  private Instant createdAt;

  @LastModifiedDate
  @Column(name = "updated_at")
  private Instant updatedAt;
}