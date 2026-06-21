package com.jesusf.paydude.repository;

import com.jesusf.paydude.entity.RefreshToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

  /**
   * Plain lookup for paths that don't mutate the row themselves — currently logout, where the
   * follow-up is a bulk UPDATE on the family (intrinsically atomic, no lock needed) rather than
   * a mutation of this specific row.
   */
  Optional<RefreshToken> findByTokenHash(String tokenHash);

  /**
   * Pessimistic row lock on the rotation path. Two concurrent {@code /refresh} calls with the
   * same raw token (an attacker racing against the legitimate client, or a buggy client
   * double-firing) serialise here: the first transaction rotates, the second waits, finds the
   * row already revoked, and trips reuse detection. Without the lock we'd have a race where
   * both rotations succeed and the chain forks.
   *
   * <p>Suffix {@code ForUpdate} matches the project convention
   * ({@code AccountRepository.findByAccountNumberForUpdate}).
   */
  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("SELECT rt FROM RefreshToken rt WHERE rt.tokenHash = :tokenHash")
  Optional<RefreshToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

  /**
   * Revokes every still-active token in a family. Called in two places:
   * <ol>
   *   <li>Reuse detection — the presented token was already revoked, so we assume the chain is
   *       compromised and kill it wholesale.</li>
   *   <li>Logout — the user signed out; the family no longer represents a legitimate session.</li>
   * </ol>
   *
   * <p>Filtering on {@code revokedAt IS NULL} keeps the operation idempotent: re-running it
   * leaves already-revoked rows untouched (their original {@code revokedAt} timestamp is
   * preserved as the "true" revocation moment, not overwritten with a later one).
   */
  @Modifying
  @Query("""
      UPDATE RefreshToken rt
      SET rt.revokedAt = :now
      WHERE rt.userId = :userId
        AND rt.familyId = :familyId
        AND rt.revokedAt IS NULL
      """)
  int revokeFamily(
      @Param("userId") Long userId,
      @Param("familyId") UUID familyId,
      @Param("now") Instant now
  );

  /**
   * Revokes every still-active token of a user, across all their families. Backs the
   * password-change flow ({@code PATCH /v1/users/me/password}, via
   * {@code RefreshTokenService.revokeAllForUser}), which must invalidate every outstanding session,
   * and is the intended hook for admin-driven "force logout from all devices".
   */
  @Modifying
  @Query("""
      UPDATE RefreshToken rt
      SET rt.revokedAt = :now
      WHERE rt.userId = :userId
        AND rt.revokedAt IS NULL
      """)
  int revokeAllByUser(@Param("userId") Long userId, @Param("now") Instant now);

  /**
   * Bulk-deletes every token whose lifetime has elapsed ({@code expiresAt < cutoff}). Backs the
   * scheduled cleanup job: an expired token can no longer authenticate, so the row is dead weight
   * once past expiry. Revoked-but-unexpired rows are deliberately left untouched — they stay inside
   * the audit window so a forensic walk-back of a reuse-detection event still has the full chain.
   *
   * <p>Safe against the self-referential {@code replaced_by_token_id} FK: expiry is monotonic along
   * a rotation chain (each rotation issues a token with a later expiry), so whenever a referenced
   * (newer) token is in the deleted set its referencing (older) token already is too — no dangling
   * reference can survive the statement. The {@code idx_refresh_tokens_expires_at} index keeps the
   * scan cheap.
   *
   * @param cutoff rows with {@code expiresAt} strictly before this instant are removed
   * @return the number of rows deleted
   */
  @Modifying
  @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :cutoff")
  int deleteByExpiresAtBefore(@Param("cutoff") Instant cutoff);
}