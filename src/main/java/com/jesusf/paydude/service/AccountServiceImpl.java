package com.jesusf.paydude.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jesusf.paydude.dto.account.AccountAuditResponse;
import com.jesusf.paydude.dto.account.AccountResponse;
import com.jesusf.paydude.dto.idempotent.AccountOperationRequest;
import com.jesusf.paydude.entity.Account;
import com.jesusf.paydude.entity.AccountAudit;
import com.jesusf.paydude.entity.IdempotencyKey;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.AuditAction;
import com.jesusf.paydude.event.IdempotencyKeyReservedEvent;
import com.jesusf.paydude.exception.BusinessException;
import com.jesusf.paydude.exception.ResourceNotFoundException;
import com.jesusf.paydude.mapper.AccountAuditMapper;
import com.jesusf.paydude.mapper.AccountMapper;
import com.jesusf.paydude.metrics.BusinessMetrics;
import com.jesusf.paydude.repository.AccountAuditRepository;
import com.jesusf.paydude.repository.AccountRepository;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.service.IdempotencyKeyService.ReservationOutcome;
import com.jesusf.paydude.util.AccountNumberGenerator;
import com.jesusf.paydude.util.AccountNumberMasker;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;

/**
 * Default {@link AccountService} implementation.
 *
 * <p>Deposits and withdrawals share a single idempotent pipeline: reserve the key, then either
 * replay the cached response or execute the operation under a pessimistic row lock and cache the
 * result. The two operations differ only in balance mutation, audit action and idempotency
 * scope — all captured on the private {@code AccountOperation} enum, so there is no
 * operation-type {@code switch} to keep in sync.
 *
 * <p>The class is {@code @Transactional(readOnly = true)}; the write paths ({@code deposit},
 * {@code withdraw}, {@code createDefaultAccount}) override that.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AccountServiceImpl implements AccountService {

  private final AccountRepository accountRepository;
  private final AccountAuditRepository auditRepository;
  private final UserRepository userRepository;
  private final AccountMapper accountMapper;
  private final AccountAuditMapper auditMapper;
  private final IdempotencyKeyService idempotencyKeyService;
  @Qualifier("responseCacheMapper")
  private final ObjectMapper responseCacheMapper;
  private final ApplicationEventPublisher applicationEventPublisher;
  private final BusinessMetrics metrics;

  private static final int MAX_ACCOUNT_NUMBER_ATTEMPTS = 5;

  @Override
  public AccountResponse getMyAccount(Long userId) {
    Account account = getValidAccount(userId);
    return accountMapper.toResponse(account);
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public AccountResponse deposit(Long userId, AccountOperationRequest request, String idempotencyKey) {
    return executeIdempotentAccountOperation(userId, request, idempotencyKey, AccountOperation.DEPOSIT);
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public AccountResponse withdraw(Long userId, AccountOperationRequest request, String idempotencyKey) {
    return executeIdempotentAccountOperation(userId, request, idempotencyKey, AccountOperation.WITHDRAW);
  }

  private AccountResponse executeIdempotentAccountOperation(
      Long userId,
      AccountOperationRequest request,
      String idempotencyKey,
      AccountOperation operation
  ) {
    ReservationOutcome outcome = idempotencyKeyService.reserveKey(
        idempotencyKey,
        userId,
        operation.operationScope(),
        request
    );

    return switch (outcome) {
      case ReservationOutcome.Replay replay -> {
        log.info("Idempotency replay: returning cached account response for key {}", idempotencyKey);
        yield replayCachedAccountResponse(replay);
      }
      case ReservationOutcome.Fresh fresh ->
          executeAccountOperation(userId, request, fresh.key(), operation);
    };
  }

  private AccountResponse executeAccountOperation(
      Long userId,
      AccountOperationRequest request,
      IdempotencyKey reservedKey,
      AccountOperation operation
  ) {
    // Publish only for a freshly reserved PENDING key. If any later step rolls back, the
    // AFTER_ROLLBACK listener marks this reservation FAILED so duplicate retries cannot hang
    // forever behind a key that looked "in progress".
    applicationEventPublisher.publishEvent(new IdempotencyKeyReservedEvent(reservedKey.getId()));

    Account account = getValidAccountForUpdate(userId);
    BigDecimal balanceBefore = account.getBalance();

    operation.applyTo(account, request.amount());
    // Redundant with dirty checking at runtime (account is managed in this transaction); kept
    // explicit so the mocked-repo unit tests can assert persistence (no dirty checking there).
    accountRepository.save(account);

    createAuditLog(account, operation.auditAction(), balanceBefore, account.getBalance(), request.amount());
    log.info("{} of {} {} on account {} (id={})",
        operation.logNoun(), request.amount(), account.getCurrency(),
        AccountNumberMasker.mask(account.getAccountNumber()), account.getId());

    AccountResponse response = accountMapper.toResponse(account);
    persistIdempotencyResponse(reservedKey, response);
    return response;
  }

  @Override
  public Page<AccountAuditResponse> getMyAuditHistory(Long userId, Pageable pageable) {
    Account account = getValidAccount(userId);

    return auditRepository.findByAccountId(account.getId(), pageable).map(auditMapper::toResponse);
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public void createDefaultAccount(Long userId) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));

    // Collision handling is a SELECT-first existence check, NOT catch-the-unique-violation-and-
    // retry: this method joins the registration transaction (BEFORE_COMMIT listener), and on
    // Postgres a constraint violation aborts the whole transaction — any retried INSERT after the
    // catch would fail with "current transaction is aborted" (the same Postgres behaviour that
    // shaped IdempotencyKeyServiceImpl.reserveKey; pinned by IdempotencyKeyReservationIT). The
    // residual SELECT-then-INSERT race window collapses against the UNIQUE constraint and fails
    // the registration — with 12 SecureRandom digits the odds are negligible, and failing one
    // registration beats committing a duplicate account number.
    for (int attempt = 1; attempt <= MAX_ACCOUNT_NUMBER_ATTEMPTS; attempt++) {
      String accountNumber = AccountNumberGenerator.generate();
      if (accountRepository.existsByAccountNumber(accountNumber)) {
        log.warn("Account number collision on attempt {}/{} for user {}: {}",
            attempt, MAX_ACCOUNT_NUMBER_ATTEMPTS, userId, AccountNumberMasker.mask(accountNumber));
        continue;
      }

      Account account = Account.builder()
          .user(user)
          .accountNumber(accountNumber)
          .balance(BigDecimal.ZERO)
          .build();

      accountRepository.saveAndFlush(account);

      log.info("Default USD account {} (id={}) created for user {}",
          AccountNumberMasker.mask(accountNumber), account.getId(), userId);
      return;
    }

    throw new IllegalStateException(
        "Could not generate a unique account number after "
            + MAX_ACCOUNT_NUMBER_ATTEMPTS + " attempts for user " + userId
    );
  }

  // --- Private helpers ---

  private Account getValidAccount(Long userId) {
    Account account = accountRepository.findByUserId(userId)
        .orElseThrow(() -> new ResourceNotFoundException("Account not found for user ID: " + userId));

    validateAccountStatus(account);
    return account;
  }

  private Account getValidAccountForUpdate(Long userId) {
    Account account = accountRepository.findByUserIdForUpdate(userId)
        .orElseThrow(() -> new ResourceNotFoundException("Account not found for user ID: " + userId));

    validateAccountStatus(account);
    return account;
  }

  private void validateAccountStatus(Account account) {
    if (!account.isActive()) {
      throw new BusinessException("Account is not active (status: " + account.getStatus() + ")");
    }
  }

  private void createAuditLog(Account account, AuditAction action, BigDecimal balanceBefore, BigDecimal balanceAfter, BigDecimal amount) {
    AccountAudit audit = AccountAudit.builder()
        .account(account)
        .action(action)
        .balanceBefore(balanceBefore)
        .balanceAfter(balanceAfter)
        .amount(amount)
        .build();

    auditRepository.save(audit);
  }

  private AccountResponse replayCachedAccountResponse(ReservationOutcome.Replay replay) {
    try {
      return responseCacheMapper.readValue(replay.cachedResponseBody(), AccountResponse.class);
    } catch (JsonProcessingException e) {
      // Null-body and "no cached response" cases are already handled inside reserveKey, so a
      // Replay here is guaranteed to carry a non-null body. Corruption of the stored JSON is the
      // only remaining failure mode and indicates a data integrity problem.
      throw new IllegalStateException(
          "Cached idempotency response is corrupted for key " + replay.keyId(), e
      );
    }
  }

  private void persistIdempotencyResponse(IdempotencyKey key, AccountResponse response) {
    String responseBody;
    try {
      responseBody = responseCacheMapper.writeValueAsString(response);
    } catch (JsonProcessingException e) {
      // The balance mutation has already succeeded inside the transaction. Marking the key
      // COMPLETED with a null body prevents a duplicate mutation; a later retry will get an
      // explicit error instead of silently re-running the operation.
      log.error("Failed to serialize response for idempotency key {}", key.getId(), e);
      responseBody = null;
    }
    idempotencyKeyService.complete(key, responseBody);
  }

  private enum AccountOperation {
    DEPOSIT("accounts.deposit", AuditAction.DEPOSIT, "Deposit") {
      @Override
      void applyTo(Account account, BigDecimal amount) {
        account.credit(amount);
      }
    },
    WITHDRAW("accounts.withdraw", AuditAction.WITHDRAW, "Withdrawal") {
      @Override
      void applyTo(Account account, BigDecimal amount) {
        account.debit(amount);
      }
    };

    private final String operationScope;
    private final AuditAction auditAction;
    private final String logNoun;

    AccountOperation(String operationScope, AuditAction auditAction, String logNoun) {
      this.operationScope = operationScope;
      this.auditAction = auditAction;
      this.logNoun = logNoun;
    }

    // Constant-specific behavior: each operation owns its balance mutation, so every per-operation
    // difference lives on the enum constant — no external switch to keep in sync.
    abstract void applyTo(Account account, BigDecimal amount);

    String operationScope() {
      return operationScope;
    }

    AuditAction auditAction() {
      return auditAction;
    }

    String logNoun() {
      return logNoun;
    }
  }
}
