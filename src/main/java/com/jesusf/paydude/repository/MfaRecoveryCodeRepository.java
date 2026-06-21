package com.jesusf.paydude.repository;

import com.jesusf.paydude.entity.MfaRecoveryCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;

/**
 * Data access for {@link MfaRecoveryCode} rows. Redemption is an atomic UPDATE (no
 * read-modify-write) so single-use holds under concurrency — the same pattern as the lockout
 * counters in {@link UserRepository}.
 */
@Repository
public interface MfaRecoveryCodeRepository extends JpaRepository<MfaRecoveryCode, Long> {

  /**
   * Redeems a recovery code: marks it used iff it belongs to this user and was never used. The
   * {@code used_at IS NULL} guard makes the operation single-use under concurrency — two racing
   * redemptions of the same code both reach this UPDATE, exactly one matches the row.
   *
   * @param userId   the authenticated owner (a code is never redeemable cross-account)
   * @param codeHash SHA-256 hex of the canonicalised submitted code
   * @param now      redemption timestamp to stamp
   * @return number of rows updated — {@code 1} when the code was valid and is now consumed,
   *         {@code 0} for an unknown, foreign, or already-used code
   */
  @Modifying
  @Query("""
      UPDATE MfaRecoveryCode c
         SET c.usedAt = :now
       WHERE c.userId = :userId
         AND c.codeHash = :codeHash
         AND c.usedAt IS NULL
      """)
  int consume(@Param("userId") Long userId,
              @Param("codeHash") String codeHash,
              @Param("now") Instant now);

  /**
   * Removes every code (used or not) for a user — on disable, and before issuing a fresh batch
   * at confirm so stale codes from an earlier enrollment can never resurface.
   *
   * @param userId the owner whose codes are purged
   * @return number of rows deleted
   */
  @Modifying
  @Query("DELETE FROM MfaRecoveryCode c WHERE c.userId = :userId")
  int deleteAllForUser(@Param("userId") Long userId);
}
