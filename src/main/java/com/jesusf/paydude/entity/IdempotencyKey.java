package com.jesusf.paydude.entity;

import com.jesusf.paydude.enums.IdempotencyKeyStatus;
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
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

/**
 * Persistent reservation that makes a money-moving operation idempotent.
 *
 * <p>A row is uniquely identified by {@code (keyValue, userId)} and inserted as
 * {@code PENDING} when an operation is reserved. {@link #requestHash} is the
 * SHA-256 of the canonical request JSON, so a retry under the same key with a
 * mutated body is detected as a conflict rather than silently replayed. On
 * success the row moves to {@code COMPLETED} and {@link #responseBody} holds the
 * serialized response that later retries return verbatim.
 *
 * <p>{@link #expiresAt} bounds retention; {@code ExpiredDataCleanupJob} bulk-deletes
 * rows once it has passed.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "idempotency_keys")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@EntityListeners(AuditingEntityListener.class)
public class IdempotencyKey {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(updatable = false)
  private Long id;

  @EqualsAndHashCode.Include
  @Column(name = "key_value", length = 255, nullable = false, updatable = false)
  private String keyValue;

  @Column(name = "user_id", nullable = false, updatable = false)
  private Long userId;

  @Column(name = "request_hash", length = 64, nullable = false, updatable = false)
  private String requestHash;
  
  @Column(name = "response_body", columnDefinition = "TEXT")
  private String responseBody;

  @Builder.Default
  @Enumerated(EnumType.STRING)
  @Column(name = "status", length = 20, nullable = false)
  private IdempotencyKeyStatus status = IdempotencyKeyStatus.PENDING;

  @CreatedDate
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;
}