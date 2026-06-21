package com.jesusf.paydude.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

/**
 * One single-use MFA recovery code — the lost-device fallback for a TOTP-enrolled account
 * (OWASP ASVS 2.8: a multi-factor scheme without a recovery mechanism becomes a support-driven
 * account-lockout generator; one with a <i>reusable</i> recovery secret is just a second password).
 *
 * <p>Only the SHA-256 hex digest of the code is persisted ({@code code_hash}), the same
 * raw-never-touches-disk convention as {@code refresh_tokens.token_hash}: the plaintext codes are
 * shown exactly once, in the {@code /v1/users/me/mfa/confirm} response. The codes are high-entropy
 * random strings, so a fast digest (rather than BCrypt) is appropriate — there is nothing
 * guessable to crack offline.
 *
 * <p>{@code usedAt} non-null means redeemed. Redemption happens through a single atomic UPDATE
 * guarded by {@code used_at IS NULL} ({@code MfaRecoveryCodeRepository.consume}), never by
 * dirty-checking this entity — two concurrent redemptions of the same code race on that guard and
 * exactly one wins.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "mfa_recovery_codes")
@EntityListeners(AuditingEntityListener.class)
public class MfaRecoveryCode {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(updatable = false)
  private Long id;

  @Column(name = "user_id", nullable = false, updatable = false)
  private Long userId;

  /** SHA-256 hex of the canonicalised code (upper-case, separators stripped). */
  @Column(name = "code_hash", length = 64, nullable = false, updatable = false)
  private String codeHash;

  /** When the code was redeemed; {@code null} while it is still valid. */
  @Column(name = "used_at")
  private Instant usedAt;

  @CreatedDate
  @Column(name = "created_at", updatable = false)
  private Instant createdAt;
}
