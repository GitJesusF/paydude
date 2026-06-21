package com.jesusf.paydude.service;

import com.jesusf.paydude.dto.account.AccountAuditResponse;
import com.jesusf.paydude.dto.idempotent.AccountOperationRequest;
import com.jesusf.paydude.dto.account.AccountResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

/**
 * Business operations on a user's bank account: balance lookup, idempotent single-account
 * money movements, audit history, and default-account provisioning.
 */
public interface AccountService {

  /**
   * @param userId the authenticated user
   * @return the user's account details
   */
  AccountResponse getMyAccount(Long userId);

  /**
   * Deposits funds into the user's account, idempotently.
   *
   * @param userId         the authenticated user
   * @param request        the amount (and optional memo) to deposit
   * @param idempotencyKey the client-supplied key; a retry with the same key replays the
   *                       original result instead of depositing again
   * @return the account state after the deposit
   */
  AccountResponse deposit(Long userId, AccountOperationRequest request, String idempotencyKey);

  /**
   * Withdraws funds from the user's account, idempotently.
   *
   * @param userId         the authenticated user
   * @param request        the amount (and optional memo) to withdraw
   * @param idempotencyKey the client-supplied key; a retry with the same key replays the
   *                       original result instead of withdrawing again
   * @return the account state after the withdrawal
   */
  AccountResponse withdraw(Long userId, AccountOperationRequest request, String idempotencyKey);

  /**
   * @param userId   the authenticated user
   * @param pageable page index, size and sort
   * @return a page of the account's balance-change audit history
   */
  Page<AccountAuditResponse> getMyAuditHistory(Long userId, Pageable pageable);

  /**
   * Opens the default account for a freshly registered user. Invoked by
   * {@code AccountEventListener} at {@code BEFORE_COMMIT}, so it shares the registration
   * transaction.
   *
   * @param userId the newly registered user
   */
  void createDefaultAccount(Long userId);
}
