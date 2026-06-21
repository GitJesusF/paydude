package com.jesusf.paydude.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jesusf.paydude.assembler.TransactionResponseAssembler;
import com.jesusf.paydude.dto.transactions.TransactionResponse;
import com.jesusf.paydude.dto.idempotent.TransferRequest;
import com.jesusf.paydude.entity.Account;
import com.jesusf.paydude.entity.AccountAudit;
import com.jesusf.paydude.entity.IdempotencyKey;
import com.jesusf.paydude.entity.Transaction;
import com.jesusf.paydude.enums.AccountStatus;
import com.jesusf.paydude.enums.AuditAction;
import com.jesusf.paydude.enums.Currency;
import com.jesusf.paydude.enums.TransactionStatus;
import com.jesusf.paydude.event.IdempotencyKeyReservedEvent;
import com.jesusf.paydude.exception.BusinessException;
import com.jesusf.paydude.exception.ResourceNotFoundException;
import com.jesusf.paydude.metrics.BusinessMetrics;
import com.jesusf.paydude.metrics.BusinessMetrics.TransferFailureReason;
import com.jesusf.paydude.repository.AccountAuditRepository;
import com.jesusf.paydude.repository.AccountRepository;
import com.jesusf.paydude.repository.TransactionRepository;
import com.jesusf.paydude.service.IdempotencyKeyService.ReservationOutcome;
import com.jesusf.paydude.util.AccountNumberMasker;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

/**
 * Default {@link TransactionService} implementation — the deadlock-free, idempotent transfer flow.
 *
 * <p>{@code transfer} reserves an idempotency key and then either replays the cached response or
 * runs {@code executeTransfer}: publish the reservation event, validate, acquire pessimistic
 * write locks on both accounts <em>in alphabetical order</em> (deadlock prevention), re-validate
 * under lock, move the balances, and record the transaction plus the two audit rows. The whole
 * attempt is wrapped in a timer so failure-path latency stays visible.
 *
 * <p>The class is {@code @Transactional(readOnly = true)}; {@code transfer} overrides it with a
 * writable {@code READ_COMMITTED} transaction.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TransactionServiceImpl implements TransactionService {

  private static final String TRANSFER_OPERATION_SCOPE = "transactions.transfer";

  private final IdempotencyKeyService idempotencyKeyService;
  private final AccountRepository accountRepository;
  private final TransactionRepository transactionRepository;
  private final AccountAuditRepository auditRepository;
  private final TransactionResponseAssembler transactionAssembler;
  // Pinned mapper dedicated to idempotency cache storage — independent from the primary
  // (HTTP responses) and from canonicalJsonMapper (request hashing). Decouples the durable
  // cache format from spring.jackson.* changes that would otherwise silently mix formats
  // across rows. See IdempotencyConfig#responseCacheMapper for the full reasoning.
  @Qualifier("responseCacheMapper")
  private final ObjectMapper responseCacheMapper;
  private final ApplicationEventPublisher applicationEventPublisher;
  private final BusinessMetrics metrics;

  @Override
  @Transactional(rollbackFor = Exception.class, isolation = Isolation.READ_COMMITTED)
  public TransactionResponse transfer(Long senderId, TransferRequest request, String idempotencyKey) {

    ReservationOutcome outcome = idempotencyKeyService.reserveKey(
        idempotencyKey,
        senderId,
        TRANSFER_OPERATION_SCOPE,
        request
    );

    // Pattern-match on the sealed outcome. The compiler enforces exhaustiveness over
    // {Fresh, Replay}, so adding a future variant forces this site to decide what it means here.
    // There is no dead branch for FAILED / PENDING / hash-mismatch — those raise a domain
    // exception inside reserveKey and never surface as a value.
    return switch (outcome) {
      // Replay path: a previous call with this same key (and matching request fingerprint) already
      // completed. Return the cached response without touching balances — that is the entire point
      // of supporting an Idempotency-Key header. We deliberately do NOT publish
      // IdempotencyKeyReservedEvent here: the listener is wired to AFTER_ROLLBACK and would, on any
      // later failure of this transaction, flip a legitimately COMPLETED key to FAILED, corrupting
      // the state of the original call.
      case ReservationOutcome.Replay replay -> {
        log.info("Idempotency replay: returning cached response for key {}", idempotencyKey);
        yield replayCachedResponse(replay);
      }
      case ReservationOutcome.Fresh fresh ->
          executeTransfer(senderId, request, idempotencyKey, fresh.key());
    };
  }

  private TransactionResponse executeTransfer(
      Long senderId,
      TransferRequest request,
      String idempotencyKey,
      IdempotencyKey reservedKey
  ) {
    // The timer wraps the ENTIRE transfer flow (including the lock and the validations that can
    // throw BusinessException) so failure-path latencies are represented too. Without this, p95
    // would reflect only successful transfers — misleading if a bug makes failures slower than
    // successes (the typical signature of timeouts).
    Timer.Sample sample = metrics.startTransferTimer();
    try {
      applicationEventPublisher.publishEvent(new IdempotencyKeyReservedEvent(reservedKey.getId()));

      validateRequestPreLock(request);

      LockedAccounts locked = lockAccountsInOrder(
          request.sourceAccountNumber(),
          request.targetAccountNumber()
      );
      validatePostLock(senderId, locked, request);

      BalanceSnapshot snapshot = executeBalanceUpdate(locked, request.amount());
      Transaction savedTransaction = recordTransactionAndAudits(locked, request, idempotencyKey, snapshot);

      TransactionResponse response = transactionAssembler.toResponse(savedTransaction, senderId);
      persistIdempotencyResponse(reservedKey, response);
      metrics.recordTransferCompleted();
      return response;
    } finally {
      metrics.stopTransferTimer(sample);
    }
  }

  @Override
  public Page<TransactionResponse> getMyTransactions(Long userId, Pageable pageable) {
    Account userAccount = accountRepository.findByUserId(userId)
        .orElseThrow(() -> new ResourceNotFoundException("Account not found for user ID: " + userId));

    Page<Transaction> transactionsPage = transactionRepository.findByAccountId(userAccount.getId(), pageable);

    return transactionsPage.map(tx -> transactionAssembler.toResponse(tx, userId));
  }

  // --- Helpers ---

  private void validateRequestPreLock(TransferRequest request) {
    // The source != target invariant is enforced by TransferRequest's compact constructor —
    // the request can never reach this point with both equal.
    // Currency.fromCode throws BusinessException if the code is invalid. Early validation that
    // does not require a DB hit.
    Currency.fromCode(request.currency());
  }

  /**
   * Acquires pessimistic write locks on both accounts in alphabetical order to prevent deadlocks.
   * Without ordering, two concurrent transfers (A→B and B→A) would each hold one lock and wait
   * for the other forever; alphabetical ordering guarantees one transaction always waits and
   * the other progresses.
   */
  private LockedAccounts lockAccountsInOrder(String sourceAccountNumber, String targetAccountNumber) {
    List<String> sorted = Stream.of(sourceAccountNumber, targetAccountNumber)
        .sorted()
        .toList();

    Account first = accountRepository.findByAccountNumberForUpdate(sorted.getFirst())
        .orElseThrow(() -> new ResourceNotFoundException("Account not found: " + sorted.getFirst()));
    Account second = accountRepository.findByAccountNumberForUpdate(sorted.getLast())
        .orElseThrow(() -> new ResourceNotFoundException("Account not found: " + sorted.getLast()));

    Account source = first.getAccountNumber().equals(sourceAccountNumber) ? first : second;
    Account target = first.getAccountNumber().equals(targetAccountNumber) ? first : second;

    log.info("Locked accounts in order: {} -> {}",
        AccountNumberMasker.mask(source.getAccountNumber()), AccountNumberMasker.mask(target.getAccountNumber()));
    return new LockedAccounts(source, target);
  }

  private void validatePostLock(Long senderId, LockedAccounts locked, TransferRequest request) {
    Account source = locked.source();
    Account target = locked.target();

    // Critical: ownership check. Without it, an attacker could pass someone else's accountNumber
    // and transfer out of their account. The JWT supplies senderId, the request supplies the
    // accountNumber; here we verify the two agree.
    if (!source.getUser().getId().equals(senderId)) {
      metrics.recordTransferFailed(TransferFailureReason.OWNERSHIP_VIOLATION);
      throw new BusinessException("Source account does not belong to the authenticated user");
    }

    if (source.getStatus() != AccountStatus.ACTIVE) {
      metrics.recordTransferFailed(TransferFailureReason.ACCOUNT_INACTIVE);
      throw new BusinessException("Source account is not active");
    }

    if (target.getStatus() != AccountStatus.ACTIVE) {
      metrics.recordTransferFailed(TransferFailureReason.ACCOUNT_INACTIVE);
      throw new BusinessException("Target account is not active");
    }

    Currency requestCurrency = Currency.fromCode(request.currency());
    if (source.getCurrency() != requestCurrency) {
      metrics.recordTransferFailed(TransferFailureReason.CURRENCY_MISMATCH);
      throw new BusinessException(
          String.format("Currency mismatch: request declared %s but source account is %s",
              requestCurrency, source.getCurrency())
      );
    }

    if (source.getCurrency() != target.getCurrency()) {
      metrics.recordTransferFailed(TransferFailureReason.CURRENCY_MISMATCH);
      throw new BusinessException(
          String.format("Cross-currency transfers not supported. Source: %s, Target: %s",
              source.getCurrency(), target.getCurrency())
      );
    }

    if (source.getBalance().compareTo(request.amount()) < 0) {
      metrics.recordTransferFailed(TransferFailureReason.INSUFFICIENT_FUNDS);
      throw new BusinessException(
          String.format("Insufficient funds. Available: %s, Required: %s",
              source.getBalance(), request.amount())
      );
    }
  }

  private BalanceSnapshot executeBalanceUpdate(LockedAccounts locked, BigDecimal amount) {
    Account source = locked.source();
    Account target = locked.target();

    BigDecimal sourceBefore = source.getBalance();
    BigDecimal targetBefore = target.getBalance();

    source.debit(amount);
    target.credit(amount);

    // Redundant with dirty checking at runtime — both accounts are managed in this transaction, so
    // Hibernate would flush the balance updates at commit anyway. Kept explicit so the mocked-repo
    // unit tests can assert persistence (no EntityManager, hence no dirty checking, in those tests).
    accountRepository.save(source);
    accountRepository.save(target);

    log.info("Transfer executed: {} {} from {} to {}",
        amount, source.getCurrency(),
        AccountNumberMasker.mask(source.getAccountNumber()), AccountNumberMasker.mask(target.getAccountNumber()));

    return new BalanceSnapshot(sourceBefore, targetBefore);
  }

  private Transaction recordTransactionAndAudits(
      LockedAccounts locked,
      TransferRequest request,
      String idempotencyKey,
      BalanceSnapshot snapshot
  ) {
    Account source = locked.source();
    Account target = locked.target();

    Transaction transaction = Transaction.builder()
        .sourceAccount(source)
        .targetAccount(target)
        .amount(request.amount())
        .currency(source.getCurrency())
        .status(TransactionStatus.COMPLETED)
        .description(request.description())
        .idempotencyKey(idempotencyKey)
        .completedAt(Instant.now())
        .build();
    Transaction saved = transactionRepository.save(transaction);

    createAuditLog(source, saved, AuditAction.TRANSFER_OUT, snapshot.sourceBefore(), source.getBalance(), request.amount());
    createAuditLog(target, saved, AuditAction.TRANSFER_IN, snapshot.targetBefore(), target.getBalance(), request.amount());

    return saved;
  }

  private TransactionResponse replayCachedResponse(ReservationOutcome.Replay replay) {
    try {
      return responseCacheMapper.readValue(replay.cachedResponseBody(), TransactionResponse.class);
    } catch (JsonProcessingException e) {
      // Stored body is corrupted. Fail loud rather than re-executing the transfer, which would
      // double-debit the user. The null-body case is already filtered by reserveKey, so a Replay
      // here is guaranteed to carry a non-null body — the only remaining failure mode is invalid
      // JSON, which is a data integrity problem, not a domain one.
      throw new IllegalStateException(
          "Cached idempotency response is corrupted for key " + replay.keyId(), e
      );
    }
  }

  private void persistIdempotencyResponse(IdempotencyKey key, TransactionResponse response) {
    String responseBody;
    try {
      responseBody = responseCacheMapper.writeValueAsString(response);
    } catch (JsonProcessingException e) {
      // Caching the response is best-effort — a serialization failure here must not roll back the
      // transfer that already succeeded. The key is still marked COMPLETED with a null body, so
      // future retries with the same key are short-circuited (they won't replay the transfer).
      log.error("Failed to serialize response for idempotency key {}", key.getId(), e);
      responseBody = null;
    }
    idempotencyKeyService.complete(key, responseBody);
  }

  private void createAuditLog(Account account, Transaction tx, AuditAction action, BigDecimal before, BigDecimal after, BigDecimal amount) {
    AccountAudit audit = AccountAudit.builder()
        .account(account)
        .transaction(tx)
        .action(action)
        .balanceBefore(before)
        .balanceAfter(after)
        .amount(amount)
        .build();
    auditRepository.save(audit);

    log.debug("Audit log for account {} (id={}) - {}: {} -> {}",
        AccountNumberMasker.mask(account.getAccountNumber()), account.getId(), action, before, after);
  }

  private record LockedAccounts(Account source, Account target) {
  }

  private record BalanceSnapshot(BigDecimal sourceBefore, BigDecimal targetBefore) {
  }
}
