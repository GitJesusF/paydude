package com.jesusf.paydude.entity;

import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
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
 * Immutable record of a single security-relevant event — the detection/forensics counterpart to
 * PayDude's prevention controls (rate limiting, lockout, breach screening, token rotation).
 *
 * <p>One row is appended for every audited event (login, logout, registration, password change,
 * account lockout, refresh-token reuse). Every column is {@code updatable = false}: a row is written
 * once and never edited, the same append-only discipline as {@link AccountAudit}.
 *
 * <p>{@link #userId} is a <b>plain column, not a foreign key</b>: an audit trail must outlive the
 * subject it describes — a closed or deleted user must not cascade away the evidence — so the link
 * to {@code users} is intentionally soft. It is {@code null} when the actor is unknown, most
 * importantly on a failed login for an unrecognised email, where {@link #principal} carries the
 * attempted identity instead (the forensic crux: which account was targeted).
 *
 * <p>What is deliberately never stored: passwords, raw or hashed tokens, full account numbers. The
 * table is admin-only ({@code GET /v1/admin/audit-events}), which is what makes storing an attempted
 * email in {@link #principal} acceptable — a threat model distinct from the application logs, which
 * are scrubbed of identifiers.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "security_audit_events")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@EntityListeners(AuditingEntityListener.class)
public class SecurityAuditEvent {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(updatable = false)
  @EqualsAndHashCode.Include
  private Long id;

  @Enumerated(EnumType.STRING)
  @Column(name = "event_type", length = 50, nullable = false, updatable = false)
  private SecurityAuditEventType eventType;

  @Enumerated(EnumType.STRING)
  @Column(name = "outcome", length = 20, nullable = false, updatable = false)
  private SecurityAuditOutcome outcome;

  // Soft link to users.id — no FK on purpose (the audit row outlives the user). Null when the actor
  // is unknown, e.g. a failed login for an unrecognised email.
  @Column(name = "user_id", updatable = false)
  private Long userId;

  // The identity the action was attempted as (typically the login email). Never a password or token.
  @Column(name = "principal", length = 255, updatable = false)
  private String principal;

  @Column(name = "ip_address", length = 45, updatable = false)
  private String ipAddress;

  @Column(name = "user_agent", length = 255, updatable = false)
  private String userAgent;

  // W3C Trace Context trace-id, copied from the MDC so an audit row links back to the request's logs.
  @Column(name = "trace_id", length = 64, updatable = false)
  private String traceId;

  // Short, non-sensitive context (e.g. "bad credentials", "family <id> revoked; 3 killed").
  @Column(name = "detail", length = 255, updatable = false)
  private String detail;

  @CreatedDate
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;
}
