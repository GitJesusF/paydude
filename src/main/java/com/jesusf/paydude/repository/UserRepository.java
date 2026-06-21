package com.jesusf.paydude.repository;

import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.UserStatus;
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
 * Data access for {@link User} entities.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

  /**
   * Looks up a user by email — the credential used at login.
   *
   * @param email the account email
   * @return the matching user, or empty if none exists
   */
  Optional<User> findByEmail(String email);

  /**
   * @param email the address to check
   * @return whether a user with this email already exists; used to reject
   *         duplicate registrations before attempting an insert
   */
  boolean existsByEmail(String email);

  /**
   * Loads a user under a {@code PESSIMISTIC_WRITE} row lock. Used by the MFA enrollment
   * confirmation, where the read-check-activate sequence (pending secret → code proof → flip
   * {@code mfaEnabled} + replace the recovery-code batch) must be serialized: two racing
   * {@code /confirm} calls would otherwise both pass the not-yet-enabled check and persist two
   * batches of valid recovery codes. {@code ForUpdate} suffix per the project convention.
   *
   * @param id the user id
   * @return the locked user, or empty if none exists
   */
  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("SELECT u FROM User u WHERE u.id = :id")
  Optional<User> findByIdForUpdate(@Param("id") Long id);

  // -----------------------------------------------------------------------------------------------
  // Account lockout (anti-bruteforce). All four operations are single atomic UPDATEs so concurrent
  // failed logins cannot lose an increment or fork the lock decision — no read-modify-write, no
  // pessimistic lock on the hot login path. Driven exclusively by LoginAttemptService.
  //
  // Bulk JPQL UPDATEs bypass dirty checking and @LastModifiedDate, so they intentionally do NOT
  // bump users.updated_at: a transient failed-attempt counter is not a profile change, and keeping
  // updated_at meaningful for real edits is worth more than auditing every wrong password here.
  // -----------------------------------------------------------------------------------------------

  /**
   * Increments the consecutive-failed-login counter for an {@code ACTIVE} account. Matches zero rows
   * for an unknown or non-active email, so it never leaks account existence.
   *
   * @param email        canonical login email
   * @param activeStatus the {@code ACTIVE} status guard (passed so the enum literal stays in Java)
   * @return number of rows updated (0 or 1)
   */
  @Modifying
  @Query("""
      UPDATE User u
         SET u.failedLoginAttempts = u.failedLoginAttempts + 1
       WHERE u.email = :email
         AND u.status = :activeStatus
      """)
  int incrementFailedLoginAttempts(@Param("email") String email,
                                   @Param("activeStatus") UserStatus activeStatus);

  /**
   * Locks the account iff it is still {@code ACTIVE} and its (already-incremented) failure count has
   * reached the threshold. Returning {@code 1} signals the transition just happened — the caller
   * uses that to emit the {@code paydude.auth.lockout} metric exactly once.
   *
   * @param email            canonical login email
   * @param activeStatus     the {@code ACTIVE} guard
   * @param lockedStatus     the {@code LOCKED} status to set
   * @param maxAttempts      consecutive-failure threshold
   * @param lockoutExpiresAt instant the temporary lock should auto-release
   * @return number of rows updated (0 if not yet at threshold, 1 if just locked)
   */
  @Modifying
  @Query("""
      UPDATE User u
         SET u.status = :lockedStatus,
             u.lockoutExpiresAt = :lockoutExpiresAt
       WHERE u.email = :email
         AND u.status = :activeStatus
         AND u.failedLoginAttempts >= :maxAttempts
      """)
  int lockIfThresholdReached(@Param("email") String email,
                             @Param("activeStatus") UserStatus activeStatus,
                             @Param("lockedStatus") UserStatus lockedStatus,
                             @Param("maxAttempts") int maxAttempts,
                             @Param("lockoutExpiresAt") Instant lockoutExpiresAt);

  /**
   * Releases a <em>temporary</em> lock whose window has elapsed, returning the account to
   * {@code ACTIVE} and clearing the counter. A permanent/administrative lock (a {@code LOCKED} row
   * with a {@code null} expiry) does not match and is left in place.
   *
   * @param email        canonical login email
   * @param activeStatus the {@code ACTIVE} status to restore
   * @param lockedStatus the {@code LOCKED} guard
   * @param now          current instant; the lock is released only when {@code lockoutExpiresAt <= now}
   * @return number of rows updated (0 or 1)
   */
  @Modifying
  @Query("""
      UPDATE User u
         SET u.status = :activeStatus,
             u.failedLoginAttempts = 0,
             u.lockoutExpiresAt = NULL
       WHERE u.email = :email
         AND u.status = :lockedStatus
         AND u.lockoutExpiresAt IS NOT NULL
         AND u.lockoutExpiresAt <= :now
      """)
  int releaseExpiredLock(@Param("email") String email,
                         @Param("activeStatus") UserStatus activeStatus,
                         @Param("lockedStatus") UserStatus lockedStatus,
                         @Param("now") Instant now);

  /**
   * Resets the failure counter and clears any temporary-lock expiry after a successful login. The
   * {@code WHERE} guard means a clean account (counter already 0, no expiry) matches zero rows, so
   * the happy path performs no real write.
   *
   * @param userId the id of the user that just authenticated
   * @return number of rows updated (0 if already clean, 1 otherwise)
   */
  @Modifying
  @Query("""
      UPDATE User u
         SET u.failedLoginAttempts = 0,
             u.lockoutExpiresAt = NULL
       WHERE u.id = :userId
         AND (u.failedLoginAttempts > 0 OR u.lockoutExpiresAt IS NOT NULL)
      """)
  int resetFailedLoginAttempts(@Param("userId") Long userId);

  /**
   * TOTP replay guard (RFC 6238 §5.2): advances {@code mfaLastUsedStep} to the step that just
   * verified, iff it is strictly newer than the stored one. Matching zero rows means the submitted
   * code's step was already consumed — the caller must reject the attempt as a replay. Atomic for
   * the same reason as the lockout counters above: two concurrent submissions of the same code
   * both reach this UPDATE, exactly one wins.
   *
   * @param userId      the user verifying a TOTP code
   * @param matchedStep the time step the submitted code matched
   * @return number of rows updated — {@code 1} when the step is fresh, {@code 0} on replay
   */
  @Modifying
  @Query("""
      UPDATE User u
         SET u.mfaLastUsedStep = :matchedStep
       WHERE u.id = :userId
         AND (u.mfaLastUsedStep IS NULL OR u.mfaLastUsedStep < :matchedStep)
      """)
  int markMfaStepUsed(@Param("userId") Long userId, @Param("matchedStep") long matchedStep);
}
