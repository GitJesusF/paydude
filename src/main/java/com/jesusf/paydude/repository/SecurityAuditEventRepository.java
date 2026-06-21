package com.jesusf.paydude.repository;

import com.jesusf.paydude.entity.SecurityAuditEvent;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;

/**
 * Data access for the append-only {@link SecurityAuditEvent} trail.
 */
@Repository
public interface SecurityAuditEventRepository extends JpaRepository<SecurityAuditEvent, Long> {

  /**
   * Paginated audit search with three optional filters. Each predicate is bypassed when its
   * argument is {@code null} ({@code :param IS NULL OR ...}), so one query backs "everything",
   * "by user", "by event type", "by outcome", and any combination — the admin read endpoint passes
   * through whatever the caller supplied. Ordering comes from the {@link Pageable} (the controller
   * defaults to {@code createdAt} descending).
   *
   * @param userId    restrict to one actor, or {@code null} for any
   * @param eventType restrict to one event kind, or {@code null} for any
   * @param outcome   restrict to {@code SUCCESS}/{@code FAILURE}, or {@code null} for any
   * @param pageable  page index, size and sort
   * @return the matching page of audit rows
   */
  @Query("""
      SELECT e FROM SecurityAuditEvent e
      WHERE (:userId IS NULL OR e.userId = :userId)
        AND (:eventType IS NULL OR e.eventType = :eventType)
        AND (:outcome IS NULL OR e.outcome = :outcome)
      """)
  Page<SecurityAuditEvent> search(@Param("userId") Long userId,
                                  @Param("eventType") SecurityAuditEventType eventType,
                                  @Param("outcome") SecurityAuditOutcome outcome,
                                  Pageable pageable);

  /**
   * Bulk-deletes rows older than the retention cutoff. Backs the scheduled retention purge
   * ({@code ExpiredDataCleanupJob} → {@code SecurityAuditService.purgeExpired}); the
   * {@code created_at} index keeps the scan cheap. Mirrors
   * {@code RefreshTokenRepository.deleteByExpiresAtBefore}.
   *
   * @param cutoff rows with {@code createdAt} strictly before this instant are removed
   * @return the number of rows deleted
   */
  @Modifying
  @Query("DELETE FROM SecurityAuditEvent e WHERE e.createdAt < :cutoff")
  int deleteByCreatedAtBefore(@Param("cutoff") Instant cutoff);
}
