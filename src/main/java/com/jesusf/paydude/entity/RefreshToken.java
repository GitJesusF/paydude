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
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Single-use refresh token, grouped into a family for revocation. Every successful rotation
 * inserts a new row with the same {@code familyId} and marks the previous row as revoked, linking
 * them via {@code replacedByTokenId}. A request that presents an already-revoked token triggers
 * family-wide revocation — the OAuth 2.1 reuse-detection mandate.
 *
 * <p>The plain token is never persisted. Only its SHA-256 hex digest lives in {@code tokenHash}.
 * A DB compromise therefore does not yield usable tokens; this mirrors how password hashes are
 * stored. Raw token values exist only in the response body to the legitimate client and in
 * application memory for the duration of a single request.
 *
 * <p>The relationship to {@link User} is modelled as a plain {@code Long userId} (no
 * {@code @ManyToOne}), matching {@link IdempotencyKey}. This entity is queried by
 * {@code tokenHash} or {@code (userId, familyId)} — never via a navigation from {@code User},
 * so a JPA association would add complexity without benefit.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "refresh_tokens")
@EntityListeners(AuditingEntityListener.class)
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class RefreshToken {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(updatable = false)
  private Long id;

  /**
   * SHA-256 hex digest of the raw token. {@code updatable = false}: once a token is recorded
   * its hash is immutable; rotation creates a new row, never edits an existing one.
   */
  @EqualsAndHashCode.Include
  @Column(name = "token_hash", length = 64, nullable = false, updatable = false, unique = true)
  private String tokenHash;

  @Column(name = "user_id", nullable = false, updatable = false)
  private Long userId;

  /**
   * Stable identifier for the rotation chain (a "session"). Every successive token born from a
   * rotation of this one inherits the same {@code familyId}. Letting us revoke a session in one
   * statement (see {@code RefreshTokenRepository.revokeFamily}) is the whole point.
   */
  @Column(name = "family_id", nullable = false, updatable = false)
  private UUID familyId;

  @Column(name = "issued_at", nullable = false, updatable = false)
  private Instant issuedAt;

  @Column(name = "expires_at", nullable = false, updatable = false)
  private Instant expiresAt;

  /**
   * Set when this token is no longer valid for any reason — successful rotation (the chain moved
   * on), logout, family-wide revocation on reuse detection, or admin action. The runtime treats
   * any non-null value as "do not accept"; the specific reason is reconstructed from context.
   */
  @Column(name = "revoked_at")
  private Instant revokedAt;

  /**
   * Forward pointer to the next token in the rotation chain. Pure audit metadata — not consulted
   * by the runtime — but invaluable for forensic walk-backs when investigating a suspected reuse
   * attack.
   */
  @Column(name = "replaced_by_token_id")
  private Long replacedByTokenId;

  /**
   * Captured at issue time for the audit trail. IPv4 maps to 15 chars, IPv6 to 45, so
   * {@code VARCHAR(45)} is the canonical safe width for either family.
   */
  @Column(name = "created_from_ip", length = 45, updatable = false)
  private String createdFromIp;

  @Column(name = "user_agent", length = 255, updatable = false)
  private String userAgent;
}