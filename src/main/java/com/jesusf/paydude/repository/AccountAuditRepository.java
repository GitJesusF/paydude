package com.jesusf.paydude.repository;

import com.jesusf.paydude.entity.AccountAudit;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Data access for {@link AccountAudit} rows — the append-only balance-change log.
 */
@Repository
public interface AccountAuditRepository extends JpaRepository<AccountAudit, Long> {

  /**
   * Pages through an account's balance-change history.
   *
   * @param accountId the account whose audit trail to read
   * @param pageable  page index, size and sort
   * @return a page of audit rows for the account
   */
  Page<AccountAudit> findByAccountId(Long accountId, Pageable pageable);
}
