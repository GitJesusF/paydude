package com.jesusf.paydude.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jesusf.paydude.dto.account.AccountResponse;
import com.jesusf.paydude.dto.idempotent.AccountOperationRequest;
import com.jesusf.paydude.entity.Account;
import com.jesusf.paydude.entity.AccountAudit;
import com.jesusf.paydude.entity.IdempotencyKey;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.AccountStatus;
import com.jesusf.paydude.enums.Currency;
import com.jesusf.paydude.enums.IdempotencyKeyStatus;
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
import com.jesusf.paydude.util.Luhn;
import org.springframework.context.ApplicationEventPublisher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.util.Optional;

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
 * Unit tests for {@link AccountServiceImpl}.
 *
 * <p>Pins the read-side contract behind {@code GET /v1/accounts/me}: an existing account is
 * mapped to {@link AccountResponse}, a missing account surfaces as a domain
 * {@link ResourceNotFoundException} that the global advice translates into HTTP 404 with the
 * project's standard {@code ProblemDetail} shape. The write-side tests pin the idempotency
 * contract for deposit/withdraw: first attempts mutate the balance and cache the response,
 * completed replays return the cached body without touching the account.
 */
@ExtendWith(MockitoExtension.class)
class AccountServiceTest {

  @Mock
  private AccountRepository accountRepository;

  @Mock
  private AccountAuditRepository auditRepository;

  // Required by createDefaultAccount (loads the owner before inserting); without this mock
  // @InjectMocks would inject null.
  @Mock
  private UserRepository userRepository;

  @Mock
  private AccountMapper accountMapper;

  @Mock
  private AccountAuditMapper auditMapper;

  @Mock
  private IdempotencyKeyService idempotencyKeyService;

  @Mock
  private ObjectMapper responseCacheMapper;

  @Mock
  private ApplicationEventPublisher applicationEventPublisher;

  @Mock
  private BusinessMetrics metrics;

  @InjectMocks
  private AccountServiceImpl accountService;

  @Test
  @DisplayName("Should return account details when account exists")
  void shouldReturnAccountDetailsSuccess() {
    // The user is an id-only reference: the response exposes no owner data, but a null
    // @ManyToOne would trip the flow.
    Long userId = 1L;
    Account mockAccount = Account.builder()
        .id(100L)
        .accountNumber("1234567890")
        .balance(new BigDecimal("1500.00"))
        .currency(Currency.USD)
        .status(AccountStatus.ACTIVE)
        .user(User.builder().id(userId).build())
        .build();

    AccountResponse expectedResponse = new AccountResponse(
        "1234567890",
        new BigDecimal("1500.00"),
        "USD",
        "ACTIVE"
    );

    when(accountRepository.findByUserId(userId)).thenReturn(Optional.of(mockAccount));
    when(accountMapper.toResponse(mockAccount)).thenReturn(expectedResponse);

    AccountResponse actualResponse = accountService.getMyAccount(userId);

    assertNotNull(actualResponse);
    assertEquals("1234567890", actualResponse.accountNumber());
    assertEquals(new BigDecimal("1500.00"), actualResponse.balance());

    verify(accountRepository).findByUserId(userId);
  }

  @Test
  @DisplayName("Should deposit once and cache the idempotent response")
  void shouldDepositOnceAndCacheIdempotentResponse() throws Exception {
    Long userId = 1L;
    String idempotencyKey = "deposit-key";
    AccountOperationRequest request = new AccountOperationRequest(new BigDecimal("25.00"), "top up");
    Account account = Account.builder()
        .id(100L)
        .accountNumber("1234567890")
        .balance(new BigDecimal("100.00"))
        .currency(Currency.USD)
        .status(AccountStatus.ACTIVE)
        .user(User.builder().id(userId).build())
        .build();
    IdempotencyKey pendingKey = IdempotencyKey.builder()
        .id(77L)
        .keyValue(idempotencyKey)
        .userId(userId)
        .status(IdempotencyKeyStatus.PENDING)
        .build();
    AccountResponse expectedResponse = new AccountResponse(
        "1234567890",
        new BigDecimal("125.00"),
        "USD",
        "ACTIVE"
    );

    when(idempotencyKeyService.reserveKey(
        eq(idempotencyKey),
        eq(userId),
        eq("accounts.deposit"),
        any(AccountOperationRequest.class)
    )).thenReturn(new ReservationOutcome.Fresh(pendingKey));
    when(accountRepository.findByUserIdForUpdate(userId)).thenReturn(Optional.of(account));
    when(accountMapper.toResponse(account)).thenReturn(expectedResponse);
    when(responseCacheMapper.writeValueAsString(expectedResponse)).thenReturn("{\"balance\":125.00}");

    AccountResponse actualResponse = accountService.deposit(userId, request, idempotencyKey);

    assertSame(expectedResponse, actualResponse);
    assertEquals(new BigDecimal("125.00"), account.getBalance());
    verify(applicationEventPublisher).publishEvent(any(IdempotencyKeyReservedEvent.class));
    verify(accountRepository).save(account);
    verify(auditRepository).save(any(AccountAudit.class));
    verify(idempotencyKeyService).complete(pendingKey, "{\"balance\":125.00}");
  }

  @Test
  @DisplayName("Should replay completed withdraw without mutating the account")
  void shouldReplayCompletedWithdrawWithoutMutatingAccount() throws Exception {
    Long userId = 1L;
    String idempotencyKey = "withdraw-key";
    String cachedBody = "{\"accountNumber\":\"1234567890\",\"balance\":80.00}";
    AccountOperationRequest request = new AccountOperationRequest(new BigDecimal("20.00"), "atm");
    AccountResponse cachedResponse = new AccountResponse(
        "1234567890",
        new BigDecimal("80.00"),
        "USD",
        "ACTIVE"
    );

    when(idempotencyKeyService.reserveKey(
        eq(idempotencyKey),
        eq(userId),
        eq("accounts.withdraw"),
        any(AccountOperationRequest.class)
    )).thenReturn(new ReservationOutcome.Replay(88L, cachedBody));
    when(responseCacheMapper.readValue(cachedBody, AccountResponse.class)).thenReturn(cachedResponse);

    AccountResponse actualResponse = accountService.withdraw(userId, request, idempotencyKey);

    assertSame(cachedResponse, actualResponse);
    verify(accountRepository, never()).findByUserIdForUpdate(anyLong());
    verify(accountRepository, never()).save(any(Account.class));
    verify(auditRepository, never()).save(any(AccountAudit.class));
    verify(applicationEventPublisher, never()).publishEvent(any());
  }

  @Test
  @DisplayName("Should reject a withdrawal beyond the balance, leaving no partial side effects")
  void shouldRejectWithdrawWhenInsufficientFunds() {
    Long userId = 1L;
    Account account = Account.builder()
        .id(100L)
        .accountNumber("1234567890")
        .balance(new BigDecimal("10.00"))
        .currency(Currency.USD)
        .status(AccountStatus.ACTIVE)
        .user(User.builder().id(userId).build())
        .build();
    AccountOperationRequest request = new AccountOperationRequest(new BigDecimal("50.00"), "too much");
    IdempotencyKey pendingKey = IdempotencyKey.builder()
        .id(77L)
        .keyValue("withdraw-key")
        .userId(userId)
        .status(IdempotencyKeyStatus.PENDING)
        .build();

    when(idempotencyKeyService.reserveKey(
        eq("withdraw-key"), eq(userId), eq("accounts.withdraw"), any(AccountOperationRequest.class)
    )).thenReturn(new ReservationOutcome.Fresh(pendingKey));
    when(accountRepository.findByUserIdForUpdate(userId)).thenReturn(Optional.of(account));

    BusinessException ex = assertThrows(BusinessException.class,
        () -> accountService.withdraw(userId, request, "withdraw-key"));
    assertTrue(ex.getMessage().contains("Insufficient funds"));

    // The reservation event was already published — by design, so the AFTER_ROLLBACK listener
    // can flip the key to FAILED — but nothing else may have happened.
    verify(applicationEventPublisher).publishEvent(any(IdempotencyKeyReservedEvent.class));
    assertEquals(new BigDecimal("10.00"), account.getBalance(),
        "balance must not change after a rejected withdrawal");
    verify(accountRepository, never()).save(any(Account.class));
    verify(auditRepository, never()).save(any(AccountAudit.class));
    verify(idempotencyKeyService, never()).complete(any(), anyString());
  }

  @Test
  @DisplayName("Should surface 404 when a deposit targets a user with no account")
  void shouldRejectDepositWhenAccountMissing() {
    Long userId = 1L;
    IdempotencyKey pendingKey = IdempotencyKey.builder()
        .id(5L)
        .keyValue("dep-key")
        .userId(userId)
        .status(IdempotencyKeyStatus.PENDING)
        .build();
    when(idempotencyKeyService.reserveKey(
        eq("dep-key"), eq(userId), eq("accounts.deposit"), any(AccountOperationRequest.class)
    )).thenReturn(new ReservationOutcome.Fresh(pendingKey));
    when(accountRepository.findByUserIdForUpdate(userId)).thenReturn(Optional.empty());

    ResourceNotFoundException ex = assertThrows(ResourceNotFoundException.class,
        () -> accountService.deposit(userId, new AccountOperationRequest(BigDecimal.TEN, "x"), "dep-key"));

    assertEquals("Account not found for user ID: 1", ex.getMessage());
    verify(auditRepository, never()).save(any(AccountAudit.class));
    verify(idempotencyKeyService, never()).complete(any(), anyString());
  }

  @Test
  @DisplayName("Should reject money operations on a non-ACTIVE account")
  void shouldRejectOperationOnInactiveAccount() {
    Long userId = 1L;
    Account frozen = Account.builder()
        .id(100L)
        .accountNumber("1234567890")
        .balance(new BigDecimal("100.00"))
        .currency(Currency.USD)
        .status(AccountStatus.FROZEN)
        .user(User.builder().id(userId).build())
        .build();
    IdempotencyKey pendingKey = IdempotencyKey.builder()
        .id(6L)
        .keyValue("frozen-key")
        .userId(userId)
        .status(IdempotencyKeyStatus.PENDING)
        .build();
    when(idempotencyKeyService.reserveKey(
        eq("frozen-key"), eq(userId), eq("accounts.withdraw"), any(AccountOperationRequest.class)
    )).thenReturn(new ReservationOutcome.Fresh(pendingKey));
    when(accountRepository.findByUserIdForUpdate(userId)).thenReturn(Optional.of(frozen));

    BusinessException ex = assertThrows(BusinessException.class,
        () -> accountService.withdraw(userId, new AccountOperationRequest(BigDecimal.TEN, "x"), "frozen-key"));

    assertTrue(ex.getMessage().contains("Account is not active"));
    assertEquals(new BigDecimal("100.00"), frozen.getBalance(),
        "a frozen account's balance must never move");
    verify(auditRepository, never()).save(any(AccountAudit.class));
  }

  @Test
  @DisplayName("Should throw ResourceNotFoundException when account does not exist")
  void shouldThrowExceptionWhenAccountNotFound() {
    // A JWT-valid user with no default account — impossible under the normal registration
    // flow, covered defensively.
    Long userId = 99L;

    when(accountRepository.findByUserId(userId)).thenReturn(Optional.empty());

    ResourceNotFoundException exception = assertThrows(
        ResourceNotFoundException.class,
        () -> accountService.getMyAccount(userId)
    );

    // The message is client-visible contract (it becomes the ProblemDetail detail field).
    assertEquals("Account not found for user ID: 99", exception.getMessage());
    verify(accountMapper, never()).toResponse(any());
  }

  // createDefaultAccount resolves account-number collisions SELECT-first (existsByAccountNumber
  // before INSERT), never catch-the-unique-violation-and-retry: it joins the registration
  // transaction (BEFORE_COMMIT listener), and on Postgres a constraint violation aborts the whole
  // transaction — any later statement would fail with "current transaction is aborted" (the same
  // behaviour that shaped reserveKey; pinned by IdempotencyKeyReservationIT).

  @Test
  @DisplayName("Should create the default account with a Luhn-valid number and zero balance")
  void shouldCreateDefaultAccount() {
    Long userId = 7L;
    when(userRepository.findById(userId)).thenReturn(Optional.of(User.builder().id(userId).build()));
    when(accountRepository.existsByAccountNumber(anyString())).thenReturn(false);

    accountService.createDefaultAccount(userId);

    ArgumentCaptor<Account> saved = ArgumentCaptor.forClass(Account.class);
    verify(accountRepository).saveAndFlush(saved.capture());
    Account account = saved.getValue();
    assertEquals(BigDecimal.ZERO, account.getBalance(), "default accounts open with zero balance");
    assertEquals(16, account.getAccountNumber().length());
    assertTrue(account.getAccountNumber().startsWith("452"), "bank prefix must be present");
    assertTrue(Luhn.isValid(account.getAccountNumber()), "generated numbers carry a Luhn check digit");
  }

  @Test
  @DisplayName("Should regenerate the account number when the candidate collides, then insert once")
  void shouldRegenerateOnAccountNumberCollision() {
    Long userId = 7L;
    when(userRepository.findById(userId)).thenReturn(Optional.of(User.builder().id(userId).build()));
    // First candidate collides with an existing row; the second is free.
    when(accountRepository.existsByAccountNumber(anyString())).thenReturn(true, false);

    accountService.createDefaultAccount(userId);

    verify(accountRepository, times(2)).existsByAccountNumber(anyString());
    verify(accountRepository, times(1)).saveAndFlush(any(Account.class));
  }

  @Test
  @DisplayName("Should give up after the retry budget when every candidate collides")
  void shouldGiveUpWhenCollisionsExhaustRetries() {
    Long userId = 7L;
    when(userRepository.findById(userId)).thenReturn(Optional.of(User.builder().id(userId).build()));
    when(accountRepository.existsByAccountNumber(anyString())).thenReturn(true);

    assertThrows(IllegalStateException.class, () -> accountService.createDefaultAccount(userId));

    // With no free candidate the INSERT is never attempted — the registration transaction stays
    // healthy and the failure surfaces as a server error, not a mid-flight constraint violation.
    verify(accountRepository, never()).saveAndFlush(any(Account.class));
  }
}
