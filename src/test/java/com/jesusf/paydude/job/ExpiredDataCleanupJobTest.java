package com.jesusf.paydude.job;

import com.jesusf.paydude.service.IdempotencyKeyService;
import com.jesusf.paydude.service.RefreshTokenService;
import com.jesusf.paydude.service.SecurityAuditService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ExpiredDataCleanupJob}.
 *
 * <p>The job is pure orchestration: capture one TTL cutoff, delegate the bulk deletes, log the
 * counts. Transactional boundaries and the actual SQL live in the services and repositories. What
 * is pinned here is the contract the schedule depends on — every table is purged on every run, and
 * the two TTL deletes (idempotency keys, refresh tokens) receive the <i>same</i> cutoff instant so a
 * row that is "expired" for one is never still "live" for the other. The audit purge derives its own
 * retention cutoff inside the service, so the job passes it no instant.
 */
@ExtendWith(MockitoExtension.class)
class ExpiredDataCleanupJobTest {

  @Mock private IdempotencyKeyService idempotencyKeyService;
  @Mock private RefreshTokenService refreshTokenService;
  @Mock private SecurityAuditService securityAuditService;

  @InjectMocks private ExpiredDataCleanupJob job;

  @Test
  @DisplayName("purges both tables with a single shared cutoff instant")
  void purgesBothTablesWithSharedCutoff() {
    // The returned counts only exercise the INFO-log branch; distinct values confirm each
    // delete is reported separately.
    when(idempotencyKeyService.deleteExpired(any())).thenReturn(3);
    when(refreshTokenService.deleteExpired(any())).thenReturn(5);
    when(securityAuditService.purgeExpired()).thenReturn(7);

    job.purgeExpiredRows();

    // The job reads Instant.now() exactly once: two separate now() calls could straddle a row's
    // expiry boundary between the deletes.
    ArgumentCaptor<Instant> idempotencyCutoff = ArgumentCaptor.forClass(Instant.class);
    ArgumentCaptor<Instant> refreshCutoff = ArgumentCaptor.forClass(Instant.class);
    verify(idempotencyKeyService).deleteExpired(idempotencyCutoff.capture());
    verify(refreshTokenService).deleteExpired(refreshCutoff.capture());

    assertEquals(idempotencyCutoff.getValue(), refreshCutoff.getValue(),
        "both TTL deletes must run against the same cutoff instant");

    // The audit purge derives its own retention cutoff inside the service, so the job just triggers it.
    verify(securityAuditService).purgeExpired();
  }

  @Test
  @DisplayName("runs both deletes even when there is nothing to purge")
  void runsBothDeletesWhenNothingToPurge() {
    // Mockito's int default is 0 — no stubs needed. The job must not skip the later deletes
    // when an earlier one finds nothing; every table is swept on every run.
    job.purgeExpiredRows();

    verify(idempotencyKeyService).deleteExpired(any());
    verify(refreshTokenService).deleteExpired(any());
    verify(securityAuditService).purgeExpired();
  }
}
