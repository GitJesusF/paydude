package com.jesusf.paydude.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jesusf.paydude.assembler.TransactionResponseAssembler;
import com.jesusf.paydude.dto.idempotent.TransferRequest;
import com.jesusf.paydude.dto.transactions.TransactionResponse;
import com.jesusf.paydude.entity.Account;
import com.jesusf.paydude.entity.AccountAudit;
import com.jesusf.paydude.entity.IdempotencyKey;
import com.jesusf.paydude.entity.Transaction;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.Currency;
import com.jesusf.paydude.enums.IdempotencyKeyStatus;
import com.jesusf.paydude.enums.TransactionStatus;
import com.jesusf.paydude.event.IdempotencyKeyReservedEvent;
import com.jesusf.paydude.exception.BusinessException;
import com.jesusf.paydude.exception.ResourceNotFoundException;
import com.jesusf.paydude.metrics.BusinessMetrics;
import com.jesusf.paydude.repository.AccountAuditRepository;
import com.jesusf.paydude.repository.AccountRepository;
import com.jesusf.paydude.repository.TransactionRepository;
import com.jesusf.paydude.service.IdempotencyKeyService.ReservationOutcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TransactionServiceImpl}.
 *
 * <p>The transfer flow is the most complex single operation in the codebase: it coordinates
 * idempotency key reservation, pessimistic locking ordered alphabetically to prevent deadlocks,
 * balance validations against fresh data, dual audit-row creation, response serialization for
 * cache, and event publication for the rollback cleanup listener. This test file exercises that
 * coordination in isolation: no Spring, no database, no HTTP. The integration test covers the
 * end-to-end path with a real Postgres instance.
 *
 * <p>Two execution paths are pinned: (1) the happy path and its primary failure mode
 * (insufficient funds), validated under {@code HappyPathAndValidations}; and (2) the replay
 * short-circuit when {@code IdempotencyKeyService.reserveKey} returns a key already in
 * {@code COMPLETED} status, validated under {@code CompletedReplayShortCircuit}. The replay
 * branch is split into a dedicated nested class because it bypasses every step of the normal
 * flow and verifying its absence requires a different set of assertions.
 */
@ExtendWith(MockitoExtension.class)
class TransactionServiceTest {

  private static final String TRANSFER_OPERATION_SCOPE = "transactions.transfer";

  @Mock private IdempotencyKeyService idempotencyKeyService;
  @Mock private AccountRepository accountRepository;
  @Mock private TransactionRepository transactionRepository;
  @Mock private AccountAuditRepository auditRepository;
  // Direction/counterparty logic lives in TransactionResponseAssembler (tested separately);
  // only the invocation is verified here.
  @Mock private TransactionResponseAssembler transactionAssembler;
  // Scripted per-test; the production mapper's round-trip is covered by IdempotencyConfigTest.
  @Mock private ObjectMapper responseCacheMapper;
  @Mock private ApplicationEventPublisher applicationEventPublisher;
  @Mock private BusinessMetrics metrics;

  private TransactionServiceImpl transactionService;

  @BeforeEach
  void setUp() {
    transactionService = new TransactionServiceImpl(
        idempotencyKeyService,
        accountRepository,
        transactionRepository,
        auditRepository,
        transactionAssembler,
        responseCacheMapper,
        applicationEventPublisher,
        metrics
    );
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers shared by nested tests.
  // ---------------------------------------------------------------------------------------------

  // Deterministic ids: Math.random() could mint duplicate ids for the two accounts in a test.
  private final AtomicLong accountIdSequence = new AtomicLong(1);

  /** Constructs an Account with the minimum fields required by the transfer flow. */
  private Account createMockAccount(Long userId, String number, BigDecimal balance) {
    return Account.builder()
        .id(accountIdSequence.getAndIncrement())
        .accountNumber(number)
        .balance(balance)
        .currency(Currency.USD)
        // Status stays ACTIVE through @Builder.Default, so the test does not need to set it.
        .user(User.builder().id(userId).build())
        .build();
  }

  /**
   * Stubs {@code reserveKey} to return a {@code Fresh} outcome wrapping a freshly built PENDING
   * key, simulating the first attempt of a transfer (i.e. the full flow must execute, not the
   * replay short-circuit).
   */
  private void stubFirstAttemptReservation() {
    // thenAnswer builds the mock response from the invocation arguments. That keeps the returned
    // IdempotencyKey aligned with the key/userId passed by the service instead of hardcoding
    // unrelated literals.
    when(idempotencyKeyService.reserveKey(anyString(), anyLong(), eq(TRANSFER_OPERATION_SCOPE), any()))
        .thenAnswer(inv -> new ReservationOutcome.Fresh(IdempotencyKey.builder()
            .id(1L)
            .keyValue(inv.getArgument(0))
            .userId(inv.getArgument(1))
            .status(IdempotencyKeyStatus.PENDING)
            .build()));
  }

  @Nested
  @DisplayName("Happy path and transfer validations")
  class HappyPathAndValidations {

    @Test
    @DisplayName("Transfer funds when balance is sufficient")
    void shouldTransferFundsSuccessfully() throws Exception {
      Long senderId = 1L;
      String targetAccountNum = "TARGET-ACC-002";
      BigDecimal transferAmount = new BigDecimal("50.00");
      String idempotencyKey = "uuid-1234-5678";

      TransferRequest request = new TransferRequest(
          "SOURCE-ACC-001", targetAccountNum, transferAmount, "USD", "Payment for rent"
      );

      Account sourceAccount = createMockAccount(senderId, "SOURCE-ACC-001", new BigDecimal("100.00"));
      Account targetAccount = createMockAccount(2L, targetAccountNum, new BigDecimal("10.00"));

      stubFirstAttemptReservation();
      // Both lock lookups are stubbed; the service acquires them in ascending accountNumber
      // order ("SOURCE..." < "TARGET...") to prevent A→B / B→A deadlocks.
      when(accountRepository.findByAccountNumberForUpdate("SOURCE-ACC-001"))
          .thenReturn(Optional.of(sourceAccount));
      when(accountRepository.findByAccountNumberForUpdate(targetAccountNum))
          .thenReturn(Optional.of(targetAccount));

      // Simulates Hibernate assigning the id on persist — the audit rows reference tx.getId().
      when(transactionRepository.save(any(Transaction.class))).thenAnswer(invocation -> {
        Transaction t = invocation.getArgument(0);
        t.setId(999L);
        return t;
      });

      TransactionResponse expectedResponse = new TransactionResponse(
          999L, "SENT", transferAmount, "USD", "Target User",
          targetAccountNum, "Payment for rent", "COMPLETED", Instant.now()
      );
      when(transactionAssembler.toResponse(any(Transaction.class), eq(senderId)))
          .thenReturn(expectedResponse);
      // Any non-null body keeps the flow going; the exact string is pinned in a dedicated test.
      when(responseCacheMapper.writeValueAsString(any()))
          .thenReturn("{\"status\":\"COMPLETED\"}");

      TransactionResponse response = transactionService.transfer(senderId, request, idempotencyKey);

      assertEquals(new BigDecimal("50.00"), sourceAccount.getBalance(),
          "Sender balance should decrease by the transferred amount");
      assertEquals(new BigDecimal("60.00"), targetAccount.getBalance(),
          "Receiver balance should increase by the transferred amount");

      assertNotNull(response);
      assertEquals("COMPLETED", response.status());

      ArgumentCaptor<Transaction> txCaptor = ArgumentCaptor.forClass(Transaction.class);
      verify(transactionRepository).save(txCaptor.capture());
      Transaction savedTx = txCaptor.getValue();
      assertEquals(idempotencyKey, savedTx.getIdempotencyKey());
      assertEquals(TransactionStatus.COMPLETED, savedTx.getStatus());
      assertEquals(transferAmount, savedTx.getAmount());

      // The dual audit is contractual: every affected account gets its own audit row, both
      // referencing the same Transaction.
      verify(auditRepository, times(2)).save(any(AccountAudit.class));
      verify(accountRepository, times(2)).save(any(Account.class));

      // IdempotencyCleanupListener listens at AFTER_ROLLBACK and marks the key FAILED if the
      // transfer transaction rolls back. Without this event, a reserved key could stay PENDING
      // permanently after a later failure.
      verify(applicationEventPublisher).publishEvent(any(IdempotencyKeyReservedEvent.class));

      // The reservation receives the explicit operation scope plus the request DTO; canonical
      // hashing happens inside IdempotencyKeyServiceImpl.
      verify(idempotencyKeyService)
          .reserveKey(eq(idempotencyKey), eq(senderId), eq(TRANSFER_OPERATION_SCOPE), eq(request));
    }

    @Test
    @DisplayName("Throws BusinessException when the issuer has insufficient funds")
    void shouldFailWhenInsufficientFunds() {
      Long senderId = 1L;
      Account sourceAccount = createMockAccount(senderId, "SRC-001", new BigDecimal("10.00"));
      Account targetAccount = createMockAccount(2L, "TGT-002", BigDecimal.ZERO);
      TransferRequest request = new TransferRequest(
          "SRC-001", "TGT-002", new BigDecimal("50.00"), "USD", "Fail test"
      );

      stubFirstAttemptReservation();
      when(accountRepository.findByAccountNumberForUpdate("SRC-001"))
          .thenReturn(Optional.of(sourceAccount));
      when(accountRepository.findByAccountNumberForUpdate("TGT-002"))
          .thenReturn(Optional.of(targetAccount));

      BusinessException ex = assertThrows(BusinessException.class, () ->
          transactionService.transfer(senderId, request, "key-123")
      );

      // contains(): the "Insufficient funds" fragment is the contract; the rest of the message
      // may be reworded freely.
      assertTrue(ex.getMessage().contains("Insufficient funds"));

      // Balance validation runs after the locks are acquired; on failure nothing may have been
      // mutated or persisted.
      assertEquals(new BigDecimal("10.00"), sourceAccount.getBalance(),
          "Balance must not change after a failed validation");
      verify(transactionRepository, never()).save(any());
      verify(auditRepository, never()).save(any());
      verify(idempotencyKeyService, never()).complete(any(), anyString());
    }

    // Self-transfer rejection (source == target) is enforced by TransferRequest's compact
    // constructor, so the service is unreachable with source == target. That invariant is
    // covered by TransferRequestTest.

    @Test
    @DisplayName("Throws BusinessException when the source account belongs to a different user — "
        + "ownership check after pessimistic lock prevents transferring from someone else's account")
    void shouldRejectTransferWhenSourceAccountBelongsToAnotherUser() {
      // The JWT proves who the caller is, not which account they may operate. Without the
      // ownership check in validatePostLock — evaluated on locked, fresh data — an authenticated
      // attacker could name any source accountNumber and drain it. Validating before the lock
      // would leave a TOCTOU window if account ownership ever changed.
      Long attackerId = 1L;
      Long victimId = 2L;

      Account victimAccount = createMockAccount(victimId, "VICTIM-ACC-001", new BigDecimal("1000.00"));
      Account attackerTargetAccount = createMockAccount(attackerId, "ATTACKER-ACC-002", BigDecimal.ZERO);

      TransferRequest maliciousRequest = new TransferRequest(
          "VICTIM-ACC-001",   // source: the victim's account
          "ATTACKER-ACC-002", // target: the attacker's own account
          new BigDecimal("500.00"),
          "USD",
          "drain"
      );

      stubFirstAttemptReservation();
      // Alphabetical lock order: ATTACKER-ACC-002 < VICTIM-ACC-001, so both stubs are needed
      // for the flow to reach the post-lock validation.
      when(accountRepository.findByAccountNumberForUpdate("VICTIM-ACC-001"))
          .thenReturn(Optional.of(victimAccount));
      when(accountRepository.findByAccountNumberForUpdate("ATTACKER-ACC-002"))
          .thenReturn(Optional.of(attackerTargetAccount));

      BusinessException ex = assertThrows(BusinessException.class, () ->
          transactionService.transfer(attackerId, maliciousRequest, "key-attack")
      );

      assertTrue(ex.getMessage().contains("does not belong to the authenticated user"),
          "Error message must explicitly state the ownership violation, not a generic 409");

      // No state mutation of any kind; the key is not completed — the AFTER_ROLLBACK listener
      // flips it to FAILED when the surrounding transaction rolls back.
      assertEquals(new BigDecimal("1000.00"), victimAccount.getBalance(),
          "Victim balance must not change after a rejected ownership check");
      assertEquals(BigDecimal.ZERO, attackerTargetAccount.getBalance(),
          "Attacker balance must not change after a rejected ownership check");
      verify(transactionRepository, never()).save(any());
      verify(auditRepository, never()).save(any());
      verify(idempotencyKeyService, never()).complete(any(), anyString());
    }

    @Test
    @DisplayName("Throws BusinessException for an unsupported currency code before touching any account")
    void shouldRejectUnsupportedCurrencyBeforeLocking() {
      Long senderId = 1L;
      TransferRequest request = new TransferRequest(
          "SRC-001", "TGT-002", new BigDecimal("10.00"), "EUR", "x"
      );
      stubFirstAttemptReservation();

      BusinessException ex = assertThrows(BusinessException.class,
          () -> transactionService.transfer(senderId, request, "key-eur"));
      assertTrue(ex.getMessage().contains("Unsupported currency"));

      // Pre-lock validation: a bad code must cost zero DB work — no lookup, no lock, no write.
      verify(accountRepository, never()).findByAccountNumberForUpdate(anyString());
      verify(transactionRepository, never()).save(any());
    }

    @Test
    @DisplayName("Throws ResourceNotFoundException when the source account number does not exist")
    void shouldFailWhenSourceAccountMissing() {
      Long senderId = 1L;
      TransferRequest request = new TransferRequest(
          "SRC-001", "TGT-002", new BigDecimal("10.00"), "USD", "x"
      );
      stubFirstAttemptReservation();
      // Alphabetical lock order: SRC-001 is looked up first; absence aborts before the second lookup.
      when(accountRepository.findByAccountNumberForUpdate("SRC-001")).thenReturn(Optional.empty());

      ResourceNotFoundException ex = assertThrows(ResourceNotFoundException.class,
          () -> transactionService.transfer(senderId, request, "key-404-src"));

      assertEquals("Account not found: SRC-001", ex.getMessage());
      verify(transactionRepository, never()).save(any());
    }

    @Test
    @DisplayName("Throws ResourceNotFoundException when the target account number does not exist")
    void shouldFailWhenTargetAccountMissing() {
      Long senderId = 1L;
      Account source = createMockAccount(senderId, "SRC-001", new BigDecimal("100.00"));
      TransferRequest request = new TransferRequest(
          "SRC-001", "TGT-002", new BigDecimal("10.00"), "USD", "x"
      );
      stubFirstAttemptReservation();
      when(accountRepository.findByAccountNumberForUpdate("SRC-001")).thenReturn(Optional.of(source));
      when(accountRepository.findByAccountNumberForUpdate("TGT-002")).thenReturn(Optional.empty());

      ResourceNotFoundException ex = assertThrows(ResourceNotFoundException.class,
          () -> transactionService.transfer(senderId, request, "key-404-tgt"));

      assertEquals("Account not found: TGT-002", ex.getMessage());
      assertEquals(new BigDecimal("100.00"), source.getBalance(),
          "the already-locked source must not be mutated when the target is missing");
      verify(transactionRepository, never()).save(any());
    }

    @Test
    @DisplayName("Throws BusinessException when the request currency does not match the source account")
    void shouldRejectCurrencyMismatch() {
      Long senderId = 1L;
      // createMockAccount builds USD accounts; the request declares MXN — valid code, wrong account.
      Account source = createMockAccount(senderId, "SRC-001", new BigDecimal("100.00"));
      Account target = createMockAccount(2L, "TGT-002", BigDecimal.ZERO);
      TransferRequest request = new TransferRequest(
          "SRC-001", "TGT-002", new BigDecimal("10.00"), "MXN", "x"
      );
      stubFirstAttemptReservation();
      when(accountRepository.findByAccountNumberForUpdate("SRC-001")).thenReturn(Optional.of(source));
      when(accountRepository.findByAccountNumberForUpdate("TGT-002")).thenReturn(Optional.of(target));

      BusinessException ex = assertThrows(BusinessException.class,
          () -> transactionService.transfer(senderId, request, "key-mxn"));

      assertTrue(ex.getMessage().contains("Currency mismatch"));
      verify(metrics).recordTransferFailed(BusinessMetrics.TransferFailureReason.CURRENCY_MISMATCH);
      assertEquals(new BigDecimal("100.00"), source.getBalance(),
          "balances must not move on a rejected currency");
      verify(transactionRepository, never()).save(any());
      verify(auditRepository, never()).save(any());
    }

    @Test
    @DisplayName("Marks the idempotency key as COMPLETED with the serialized response body")
    void shouldCompleteIdempotencyKeyWithResponseBody() throws Exception {
      // Pins that the COMPLETED transition + body caching go through
      // IdempotencyKeyService.complete(), keeping the storage details centralized there.
      Long senderId = 1L;
      Account source = createMockAccount(senderId, "SOURCE-ACC-001", new BigDecimal("500.00"));
      Account target = createMockAccount(2L, "TARGET-ACC-002", BigDecimal.ZERO);
      TransferRequest request = new TransferRequest(
          "SOURCE-ACC-001", "TARGET-ACC-002", new BigDecimal("200.00"), "USD", "rent"
      );

      stubFirstAttemptReservation();
      when(accountRepository.findByAccountNumberForUpdate("SOURCE-ACC-001"))
          .thenReturn(Optional.of(source));
      when(accountRepository.findByAccountNumberForUpdate("TARGET-ACC-002"))
          .thenReturn(Optional.of(target));
      when(transactionRepository.save(any(Transaction.class))).thenAnswer(inv -> {
        Transaction t = inv.getArgument(0);
        t.setId(42L);
        return t;
      });
      TransactionResponse response = new TransactionResponse(
          42L, "SENT", new BigDecimal("200.00"), "USD", "Target",
          "TARGET-ACC-002", "rent", "COMPLETED", Instant.now()
      );
      when(transactionAssembler.toResponse(any(Transaction.class), eq(senderId)))
          .thenReturn(response);

      String serializedBody = "{\"id\":42,\"status\":\"COMPLETED\"}";
      when(responseCacheMapper.writeValueAsString(response)).thenReturn(serializedBody);

      transactionService.transfer(senderId, request, "key-abc");

      ArgumentCaptor<IdempotencyKey> keyCaptor = ArgumentCaptor.forClass(IdempotencyKey.class);
      ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
      verify(idempotencyKeyService).complete(keyCaptor.capture(), bodyCaptor.capture());

      assertEquals("key-abc", keyCaptor.getValue().getKeyValue());
      assertEquals(serializedBody, bodyCaptor.getValue(),
          "The serialized body must be passed verbatim so a future retry can return the cached response");
    }
  }

  /**
   * The short-circuit must be complete: deserialize the cached body, return it, touch nothing
   * else. This class pins the historical bug where a COMPLETED key was ignored and the transfer
   * re-executed — duplicating the financial operation.
   */
  @Nested
  @DisplayName("Replay path: the key is already COMPLETED")
  class CompletedReplayShortCircuit {

    /**
     * Local helper that simulates the {@code Replay} outcome returned by
     * {@link IdempotencyKeyServiceImpl#reserveKey} when an existing key with matching hash and
     * COMPLETED status is found. {@link TransactionServiceImpl} must detect the variant and
     * return immediately with the cached body, never reaching the transfer execution path.
     */
    private void stubCompletedReservation(String keyValue, Long userId, String cachedBody) {
      when(idempotencyKeyService.reserveKey(eq(keyValue), eq(userId), eq(TRANSFER_OPERATION_SCOPE), any()))
          .thenReturn(new ReservationOutcome.Replay(99L, cachedBody));
    }

    @Test
    @DisplayName("Returns the cached response without executing the transfer or publishing the event")
    void shouldReturnCachedResponseWithoutExecutingTheTransfer() throws Exception {
      Long senderId = 1L;
      String idempotencyKey = "key-replay";
      String cachedBody = "{\"id\":42,\"status\":\"COMPLETED\",\"amount\":200.00}";
      TransferRequest request = new TransferRequest(
          "SOURCE-ACC-001", "TARGET-ACC-002", new BigDecimal("200.00"), "USD", "rent"
      );

      stubCompletedReservation(idempotencyKey, senderId, cachedBody);

      // The deserialized object is scripted; the real serialize/deserialize round-trip is
      // covered by IdempotencyConfigTest against the production mapper.
      TransactionResponse cachedResponse = new TransactionResponse(
          42L, "SENT", new BigDecimal("200.00"), "USD", "Target",
          "TARGET-ACC-002", "rent", "COMPLETED", Instant.now()
      );
      when(responseCacheMapper.readValue(cachedBody, TransactionResponse.class))
          .thenReturn(cachedResponse);

      TransactionResponse response = transactionService.transfer(senderId, request, idempotencyKey);

      assertSame(cachedResponse, response,
          "The response must be the exact instance deserialized from the cache, not a reconstruction");

      // The short-circuit must be complete, not partial: no repository of the transfer flow
      // may be touched.
      verify(accountRepository, never()).findByUserId(anyLong());
      verify(accountRepository, never()).findByAccountNumberForUpdate(anyString());
      verify(accountRepository, never()).save(any());
      verify(transactionRepository, never()).save(any());
      verify(auditRepository, never()).save(any());

      // No IdempotencyKeyReservedEvent: if it were published and the surrounding transaction
      // later rolled back, the cleanup listener would mark a legitimately COMPLETED key as
      // FAILED, breaking every future retry with that key.
      verify(applicationEventPublisher, never()).publishEvent(any());

      // complete() on an already-completed key would be a bug signal in itself.
      verify(idempotencyKeyService, never()).complete(any(), anyString());
    }

    // The "COMPLETED key without responseBody" scenario is covered by
    // IdempotencyKeyServiceTest.shouldRejectReplayWhenStoredBodyIsNull: ReservationOutcome.Replay
    // guarantees a non-null body by contract (requireNonNull in its constructor), so the
    // rejection happens inside reserveKey — it is no longer this service's job to detect it.

    @Test
    @DisplayName("Throws IllegalStateException when the cached responseBody is corrupted")
    void shouldRejectReplayWhenCachedBodyIsCorrupted() throws Exception {
      // A body that serialized fine should deserialize fine; a parse failure means the row was
      // corrupted (manual edit, migration bug, truncation). Policy is fail-fast with
      // IllegalStateException: re-executing would duplicate the debit, reconstructing the
      // response would break idempotency.
      Long senderId = 1L;
      String idempotencyKey = "key-corrupt";
      String corruptedBody = "{ this is not valid json";
      TransferRequest request = new TransferRequest(
          "SRC", "TGT", new BigDecimal("10.00"), "USD", "x"
      );

      stubCompletedReservation(idempotencyKey, senderId, corruptedBody);

      // JsonProcessingException is checked and abstract; the empty anonymous subclass is the
      // standard way to throw it from a stub.
      when(responseCacheMapper.readValue(corruptedBody, TransactionResponse.class))
          .thenThrow(new JsonProcessingException("simulated parse error") {});

      assertThrows(IllegalStateException.class, () ->
          transactionService.transfer(senderId, request, idempotencyKey)
      );

      verify(accountRepository, never()).findByUserId(anyLong());
      verify(transactionRepository, never()).save(any());
      verify(applicationEventPublisher, never()).publishEvent(any());
    }
  }
}
