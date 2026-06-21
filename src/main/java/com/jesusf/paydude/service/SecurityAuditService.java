package com.jesusf.paydude.service;

import com.jesusf.paydude.dto.audit.SecurityAuditEventResponse;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

/**
 * Records and reads the append-only security audit trail — the detection/forensics counterpart to
 * PayDude's prevention controls (rate limiting, lockout, breach screening, token rotation),
 * satisfying OWASP ASVS V7.
 *
 * <p>{@link #record} is called from the security event sites (login, logout, register, password
 * change, lockout, token reuse). It is durable and fail-safe by design: the row is written in a
 * {@code REQUIRES_NEW} transaction so it survives the rollback of a FAILED login (the event we most
 * need to keep), and any failure to write is swallowed so auditing can never break the operation it
 * observes. IP / User-Agent / trace id are resolved from the current request, so callers pass only
 * the semantic fields.
 */
public interface SecurityAuditService {

  /**
   * Appends one audit row. Request context (IP, User-Agent, trace id) is resolved internally.
   *
   * @param type      what happened
   * @param outcome   how it ended ({@code SUCCESS} / {@code FAILURE})
   * @param userId    the acting/affected user id when known, else {@code null} (e.g. a failed login
   *                  for an unrecognised email)
   * @param principal the identity the action was attempted as (typically the login email), or
   *                  {@code null} — never a password or token
   * @param detail    short, non-sensitive context, or {@code null}
   */
  void record(SecurityAuditEventType type, SecurityAuditOutcome outcome,
              Long userId, String principal, String detail);

  /**
   * Reads a page of the audit trail with three optional filters (any may be {@code null}). Backs the
   * admin endpoint {@code GET /v1/admin/audit-events}.
   *
   * @param userId    restrict to one actor, or {@code null} for any
   * @param eventType restrict to one event kind, or {@code null} for any
   * @param outcome   restrict to {@code SUCCESS}/{@code FAILURE}, or {@code null} for any
   * @param pageable  page index, size and sort
   * @return the matching page of audit rows as response DTOs
   */
  Page<SecurityAuditEventResponse> findEvents(Long userId, SecurityAuditEventType eventType,
                                              SecurityAuditOutcome outcome, Pageable pageable);

  /**
   * Deletes audit rows older than the configured retention window
   * ({@code application.security.audit.retention}). Backs the scheduled {@code ExpiredDataCleanupJob}.
   *
   * @return the number of rows purged
   */
  int purgeExpired();
}
