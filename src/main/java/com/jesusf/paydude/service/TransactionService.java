package com.jesusf.paydude.service;

import com.jesusf.paydude.dto.transactions.TransactionResponse;
import com.jesusf.paydude.dto.idempotent.TransferRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

/**
 * Business operations for moving money between accounts and reading transaction history.
 */
public interface TransactionService {

  /**
   * Executes a transfer from the sender's account to another account, idempotently and
   * deadlock-free.
   *
   * @param senderId       the authenticated user initiating the transfer
   * @param request        the transfer details (target account, amount, currency, memo)
   * @param idempotencyKey the client-supplied key; a retry with the same key replays the
   *                       original result instead of transferring again
   * @return the resulting transaction, rendered from the sender's perspective
   */
  TransactionResponse transfer(Long senderId, TransferRequest request, String idempotencyKey);

  /**
   * @param userId   the authenticated user
   * @param pageable page index, size and sort
   * @return a page of the user's transactions, each rendered from that user's perspective
   */
  Page<TransactionResponse> getMyTransactions(Long userId, Pageable pageable);
}
