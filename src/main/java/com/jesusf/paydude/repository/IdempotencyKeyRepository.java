package com.jesusf.paydude.repository;

import com.jesusf.paydude.entity.IdempotencyKey;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

/**
 * Data access for {@link IdempotencyKey} reservations.
 */
@Repository
public interface IdempotencyKeyRepository extends JpaRepository<IdempotencyKey, Long> {

  /**
   * Loads the reservation for a {@code (keyValue, userId)} pair under a {@code PESSIMISTIC_WRITE}
   * row lock — the table's unique constraint.
   *
   * <p>Scoping by {@code userId} is a security boundary: it prevents one user's idempotency key from
   * ever colliding with, or replaying, another's.
   *
   * <p>The lock is what makes {@code reserveKey} concurrency-safe once a row exists: racing retries —
   * and a racing reclaim of an expired row — serialize here, so the replay/reclaim decision is taken
   * by exactly one caller and the row can never fork. {@code reserveKey} looks up <i>before</i>
   * inserting (rather than insert-first) because a UNIQUE violation aborts the transaction on
   * Postgres, which would break any recovery query issued afterwards. {@code ForUpdate} suffix
   * matches the project convention ({@code AccountRepository.findByAccountNumberForUpdate}).
   *
   * @param keyValue the client-supplied {@code Idempotency-Key} header value
   * @param userId   the authenticated user's id
   * @return the existing reservation, or empty if this is the first use
   */
  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("SELECT k FROM IdempotencyKey k WHERE k.keyValue = :keyValue AND k.userId = :userId")
  Optional<IdempotencyKey> findByKeyValueAndUserIdForUpdate(
      @Param("keyValue") String keyValue, @Param("userId") Long userId);

  /**
   * Bulk-deletes every reservation whose TTL has elapsed ({@code expiresAt < cutoff}). Backs the
   * scheduled cleanup job: an expired row is past its retry window, so removing it both bounds
   * table growth and restores true TTL semantics — once the row is gone, the same
   * {@code (keyValue, userId)} can be reserved fresh again instead of being blocked forever by a
   * stale {@code COMPLETED}/{@code FAILED}/{@code PENDING} row.
   *
   * <p>{@code @Modifying} issues a single bulk {@code DELETE} with no entity loading; the
   * {@code idx_idempotency_expires_at} index keeps the scan cheap.
   *
   * @param cutoff rows with {@code expiresAt} strictly before this instant are removed
   * @return the number of rows deleted
   */
  @Modifying
  @Query("DELETE FROM IdempotencyKey k WHERE k.expiresAt < :cutoff")
  int deleteByExpiresAtBefore(@Param("cutoff") Instant cutoff);
}
