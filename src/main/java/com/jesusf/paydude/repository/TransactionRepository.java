package com.jesusf.paydude.repository;

import com.jesusf.paydude.entity.Transaction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Data access for {@link Transaction} entities.
 */
@Repository
public interface TransactionRepository extends JpaRepository<Transaction, Long> {

  /**
   * Pages through every transaction an account took part in, on either side.
   *
   * <p>The {@code @EntityGraph} eagerly fetches both accounts and their owners
   * in the same query. Without it, the assembler rendering each row would
   * trigger a lazy load per transaction — the classic N+1 — since
   * {@code spring.jpa.open-in-view=false} closes the persistence context before
   * the response is built.
   *
   * @param accountId the account to filter on (matched as source or target)
   * @param pageable  page index, size and sort
   * @return a page of transactions involving the account
   */
  @EntityGraph(attributePaths = {"sourceAccount.user", "targetAccount.user"})
  @Query("SELECT t FROM Transaction t WHERE t.sourceAccount.id = :accountId OR t.targetAccount.id = :accountId")
  Page<Transaction> findByAccountId(@Param("accountId") Long accountId, Pageable pageable);
}
