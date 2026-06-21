package com.jesusf.paydude.repository;

import com.jesusf.paydude.entity.Account;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Data access for {@link Account} entities.
 *
 * <p>Lookups come in two flavours. The plain {@code findBy*} methods are for
 * read-only paths. The {@code *ForUpdate} methods acquire a
 * {@code PESSIMISTIC_WRITE} row lock and are mandatory before any balance
 * mutation: holding the lock for the duration of the transaction is what
 * serializes concurrent money movements against the same account.
 *
 * <p><b>Single-account assumption.</b> {@link #findByUserId} and {@link #findByUserIdForUpdate}
 * key only on the user and return a single {@link Optional}, which is correct only while every
 * user owns exactly one (USD) account. The schema's {@code UNIQUE (user_id, currency)} permits
 * one account per currency, so before multi-currency ships these must become currency-aware
 * (e.g. {@code findByUserIdAndCurrency}) — otherwise a second account makes the lookup throw a
 * non-unique result.
 */
@Repository
public interface AccountRepository extends JpaRepository<Account, Long> {

  /**
   * Loads an account by number under a {@code PESSIMISTIC_WRITE} lock.
   *
   * <p>Used by the transfer flow. To avoid the classic circular-wait deadlock
   * between two opposing transfers, callers must acquire the locks on the two
   * accounts in a consistent order — alphabetically by {@code accountNumber}.
   *
   * @param accountNumber the 16-digit account number
   * @return the locked account, or empty if none exists
   */
  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("SELECT a FROM Account a WHERE a.accountNumber = :accountNumber")
  Optional<Account> findByAccountNumberForUpdate(@Param("accountNumber") String accountNumber);

  /**
   * Loads a user's account under a {@code PESSIMISTIC_WRITE} lock.
   *
   * <p>Used by the single-account deposit and withdrawal flows, where only one
   * account is locked so deadlock ordering does not apply.
   *
   * @param userId the owning user's id
   * @return the locked account, or empty if none exists
   */
  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("SELECT a FROM Account a WHERE a.user.id = :userId")
  Optional<Account> findByUserIdForUpdate(@Param("userId") Long userId);

  /** Read-only lookup by account number. */
  Optional<Account> findByAccountNumber(String accountNumber);

  /** Read-only lookup of a user's account. */
  Optional<Account> findByUserId(Long userId);

  /**
   * @param accountNumber a candidate account number
   * @return whether the number is already taken; checked by
   *         {@code AccountServiceImpl.createDefaultAccount} before inserting, so the
   *         rare collision regenerates instead of aborting the registration transaction
   *         (a Postgres unique violation poisons the whole transaction)
   */
  boolean existsByAccountNumber(String accountNumber);
}
