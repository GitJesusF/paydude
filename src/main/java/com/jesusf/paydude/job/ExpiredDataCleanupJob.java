package com.jesusf.paydude.job;

import com.jesusf.paydude.service.IdempotencyKeyService;
import com.jesusf.paydude.service.RefreshTokenService;
import com.jesusf.paydude.service.SecurityAuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Scheduled purge of rows that have outlived their lifetime: expired {@code idempotency_keys},
 * expired {@code refresh_tokens}, and {@code security_audit_events} past their retention window.
 *
 * <p>Both tables accumulate rows unless old data is purged. The idempotency reservation path
 * reclaims expired rows when the same key is reused, but cold expired rows would otherwise remain
 * in storage indefinitely. Refresh-token rows are likewise retained after expiry/revocation for the
 * audit window. Left unattended both tables grow without bound; this job is the storage-bound half
 * of the TTL contract. Purging an expired idempotency key preserves true TTL semantics too: once the
 * row is gone the same key can be reserved fresh again.
 *
 * <p>Each table is delegated to its owning service so the bulk {@code DELETE} runs inside that
 * service's own write transaction (behind the relevant index). The three deletes are independent and
 * intentionally not wrapped in a shared transaction — a failure purging one table must not roll back
 * the others. The audit purge differs from the other two: it deletes by a retention window
 * ({@code now − application.security.audit.retention}) rather than a per-row {@code expires_at} TTL,
 * so the audit service computes its own cutoff.
 *
 * <p>Cadence is the cron {@code application.cleanup.cron} (default 03:00 UTC daily), evaluated in
 * UTC for deterministic behavior across deploys and time zones. {@code SchedulingConfig} enables
 * the scheduling machinery; the {@code test} profile sets the cron to {@code "-"} so the job is
 * never triggered during integration tests.
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class ExpiredDataCleanupJob {

  private final IdempotencyKeyService idempotencyKeyService;
  private final RefreshTokenService refreshTokenService;
  private final SecurityAuditService securityAuditService;

  /**
   * Deletes idempotency keys and refresh tokens whose {@code expiresAt} is before "now" (the TTL
   * cutoff is captured once so both share the same instant), then purges audit events past their
   * retention window (the audit service derives its own {@code now − retention} cutoff). Counts are
   * logged at {@code INFO} only when something was actually purged, to keep an idle nightly run quiet.
   */
  @Scheduled(cron = "${application.cleanup.cron}", zone = "UTC")
  public void purgeExpiredRows() {
    Instant cutoff = Instant.now();
    int idempotencyKeys = idempotencyKeyService.deleteExpired(cutoff);
    int refreshTokens = refreshTokenService.deleteExpired(cutoff);
    // Audit rows are purged by a retention window, not the TTL cutoff above, so the service computes
    // its own cutoff from application.security.audit.retention.
    int auditEvents = securityAuditService.purgeExpired();

    if (idempotencyKeys > 0 || refreshTokens > 0 || auditEvents > 0) {
      log.info("Expired-row cleanup removed {} idempotency key(s) and {} refresh token(s) (TTL cutoff={}); "
              + "{} audit event(s) past retention",
          idempotencyKeys, refreshTokens, cutoff, auditEvents);
    } else {
      log.debug("Expired-row cleanup found nothing to purge (cutoff={})", cutoff);
    }
  }
}
