package com.jesusf.paydude.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jesusf.paydude.dto.account.AccountAuditResponse;
import com.jesusf.paydude.dto.account.AccountResponse;
import com.jesusf.paydude.dto.idempotent.AccountOperationRequest;
import com.jesusf.paydude.exception.RateLimitExceededException;
import com.jesusf.paydude.security.CustomUserDetailsService;
import com.jesusf.paydude.security.JwtService;
import com.jesusf.paydude.security.ratelimit.AuthRateLimiter;
import com.jesusf.paydude.security.ratelimit.WriteRateLimiter;
import com.jesusf.paydude.service.AccountService;
import com.jesusf.paydude.support.WithMockSecurityUser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web-layer tests for {@link AccountController}.
 *
 * <p>Pins five contracts: (1) {@code GET /v1/accounts/me} returns the account DTO as JSON;
 * (2) {@code POST /v1/accounts/deposit} and {@code /withdraw} delegate to {@link AccountService}
 * only after the per-user write limiter allows the request; (3) exhausted write buckets return
 * 429 before any service call; (4) the same endpoints reject a missing or malformed key as 400
 * before any service call; (5) {@code GET /v1/accounts/me/history} maps the {@code Page<T>}
 * returned by the service into a framework-agnostic {@code PagedResponse<T>} envelope before
 * serialization.
 */
@WebMvcTest(controllers = AccountController.class)
@AutoConfigureMockMvc(addFilters = false)
class AccountControllerTest {

  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper objectMapper;

  @MockitoBean private AccountService accountService;
  @MockitoBean private JwtService jwtService;
  @MockitoBean private CustomUserDetailsService userDetailsService;
  // The slice scans all Filter @Components, so IpRateLimitFilter is constructed (though never
  // run with addFilters=false) and its AuthRateLimiter dependency must be satisfied.
  @MockitoBean private AuthRateLimiter authRateLimiter;
  // Direct dependency of AccountController (per-user throttle on deposit/withdraw). Its
  // enforceWriteByUser is void, so Mockito's default (do nothing) lets the happy paths through;
  // the throttling tests use doThrow to simulate a drained bucket.
  @MockitoBean private WriteRateLimiter writeRateLimiter;

  // Matches @WithMockSecurityUser's default id.
  private static final Long MOCK_USER_ID = 1L;

  @Test
  @DisplayName("GET /accounts/me - Should return the authenticated user's account")
  @WithMockSecurityUser
  void shouldReturnMyAccount() throws Exception {
    AccountResponse mockResponse = new AccountResponse(
        "1234567890", new BigDecimal("1500.00"), "USD", "ACTIVE"
    );

    when(accountService.getMyAccount(eq(MOCK_USER_ID))).thenReturn(mockResponse);

    mockMvc.perform(get("/v1/accounts/me"))

        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accountNumber").value("1234567890"))
        .andExpect(jsonPath("$.balance").value(1500.00))
        .andExpect(jsonPath("$.status").value("ACTIVE"));
  }

  @Test
  @DisplayName("POST /accounts/deposit - Should succeed with valid data and Idempotency Key")
  @WithMockSecurityUser
  void shouldDepositSuccessfully() throws Exception {
    // The Idempotency-Key header is @Pattern-validated as a UUID before the handler body runs.
    String idempotencyKey = "550e8400-e29b-41d4-a716-446655440000";

    AccountOperationRequest request = new AccountOperationRequest(new BigDecimal("250.00"), "Paycheck");
    AccountResponse mockResponse = new AccountResponse(
        "1234567890", new BigDecimal("1750.00"), "USD", "ACTIVE"
    );

    when(accountService.deposit(eq(MOCK_USER_ID), any(AccountOperationRequest.class), eq(idempotencyKey)))
        .thenReturn(mockResponse);

    mockMvc.perform(post("/v1/accounts/deposit")
            .header("Idempotency-Key", idempotencyKey)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isOk())
        .andExpect(jsonPath("$.balance").value(1750.00))
        .andExpect(jsonPath("$.status").value("ACTIVE"));

    verify(writeRateLimiter).enforceWriteByUser(eq(MOCK_USER_ID), anyString());
  }

  @Test
  @DisplayName("POST /accounts/withdraw - Should succeed with valid data and Idempotency Key")
  @WithMockSecurityUser
  void shouldWithdrawSuccessfully() throws Exception {
    String idempotencyKey = "550e8400-e29b-41d4-a716-446655440000";

    AccountOperationRequest request = new AccountOperationRequest(new BigDecimal("100.00"), "ATM");
    AccountResponse mockResponse = new AccountResponse(
        "1234567890", new BigDecimal("1400.00"), "USD", "ACTIVE"
    );

    when(accountService.withdraw(eq(MOCK_USER_ID), any(AccountOperationRequest.class), eq(idempotencyKey)))
        .thenReturn(mockResponse);

    mockMvc.perform(post("/v1/accounts/withdraw")
            .header("Idempotency-Key", idempotencyKey)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isOk())
        .andExpect(jsonPath("$.balance").value(1400.00));

    verify(writeRateLimiter).enforceWriteByUser(eq(MOCK_USER_ID), anyString());
  }

  @Test
  @DisplayName("POST /accounts/deposit - Should fail 429 when the per-user write throttle is exhausted")
  @WithMockSecurityUser
  void shouldRejectDepositWhenWriteRateLimited() throws Exception {
    // The key is a valid UUID on purpose: the 429 must come from the drained bucket, not from
    // header validation (which is evaluated first).
    String idempotencyKey = "550e8400-e29b-41d4-a716-446655440000";
    AccountOperationRequest request = new AccountOperationRequest(new BigDecimal("10.00"), "memo");

    doThrow(new RateLimitExceededException("Too many account operations.", 60L))
        .when(writeRateLimiter).enforceWriteByUser(eq(MOCK_USER_ID), anyString());

    mockMvc.perform(post("/v1/accounts/deposit")
            .header("Idempotency-Key", idempotencyKey)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isTooManyRequests())
        .andExpect(header().exists("Retry-After"));

    // The throttle cuts the flow before any business work.
    verify(accountService, never()).deposit(any(), any(), any());
  }

  @Test
  @DisplayName("POST /accounts/withdraw - Should fail 429 when the per-user write throttle is exhausted")
  @WithMockSecurityUser
  void shouldRejectWithdrawWhenWriteRateLimited() throws Exception {
    // Symmetric coverage with deposit: withdrawal is also a money-moving write and must be stopped
    // by the same per-user bucket before the service can reserve idempotency keys or lock accounts.
    String idempotencyKey = "550e8400-e29b-41d4-a716-446655440000";
    AccountOperationRequest request = new AccountOperationRequest(new BigDecimal("10.00"), "ATM");

    doThrow(new RateLimitExceededException("Too many account operations.", 60L))
        .when(writeRateLimiter).enforceWriteByUser(eq(MOCK_USER_ID), anyString());

    mockMvc.perform(post("/v1/accounts/withdraw")
            .header("Idempotency-Key", idempotencyKey)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isTooManyRequests())
        .andExpect(header().exists("Retry-After"));

    verify(accountService, never()).withdraw(any(), any(), any());
  }

  @Test
  @DisplayName("POST /accounts/deposit - Should fail 400 if Idempotency Key is missing")
  @WithMockSecurityUser
  void shouldFailDepositWithoutIdempotencyKey() throws Exception {
    // @RequestHeader without a default → MissingRequestHeaderException → 400; the service is
    // never invoked.
    AccountOperationRequest request = new AccountOperationRequest(new BigDecimal("50.00"), "memo");

    mockMvc.perform(post("/v1/accounts/deposit")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isBadRequest());

    verify(accountService, never()).deposit(any(), any(), any());
  }

  @Test
  @DisplayName("POST /accounts/withdraw - Should fail 400 if Idempotency Key is not a valid UUID")
  @WithMockSecurityUser
  void shouldFailWithdrawWithMalformedIdempotencyKey() throws Exception {
    // Header present but not a UUID: the @Pattern rejects it with ConstraintViolationException,
    // translated to the same 400.
    AccountOperationRequest request = new AccountOperationRequest(new BigDecimal("50.00"), "memo");

    mockMvc.perform(post("/v1/accounts/withdraw")
            .header("Idempotency-Key", "not-a-uuid")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isBadRequest());

    verify(accountService, never()).withdraw(any(), any(), any());
  }

  @Test
  @DisplayName("GET /accounts/me/history - Should map Page to PagedResponse envelope before serializing")
  @WithMockSecurityUser
  void shouldReturnAuditHistory() throws Exception {
    // PageImpl's JSON is not a stable contract (Boot 3.2+ warns on serializing it); the
    // controller maps to the six-field PagedResponse envelope instead.
    AccountAuditResponse audit = new AccountAuditResponse(
        1L, "DEPOSIT", new BigDecimal("250.00"), new BigDecimal("1500.00"), new BigDecimal("1750.00"),
        null, Instant.now()
    );
    Page<AccountAuditResponse> mockPage = new PageImpl<>(List.of(audit), PageRequest.of(0, 20), 1);

    when(accountService.getMyAuditHistory(eq(MOCK_USER_ID), any(Pageable.class)))
        .thenReturn(mockPage);

    mockMvc.perform(get("/v1/accounts/me/history")
            .param("page", "0")
            .param("size", "20"))

        .andExpect(status().isOk())
        .andExpect(jsonPath("$.content[0].action").value("DEPOSIT"))
        .andExpect(jsonPath("$.page").value(0))
        .andExpect(jsonPath("$.size").value(20))
        .andExpect(jsonPath("$.totalElements").value(1))
        .andExpect(jsonPath("$.totalPages").value(1))
        .andExpect(jsonPath("$.hasNext").value(false))
        // Internal PageImpl fields must not leak; reverting the mapping would trip these.
        .andExpect(jsonPath("$.pageable").doesNotExist())
        .andExpect(jsonPath("$.sort").doesNotExist())
        .andExpect(jsonPath("$.empty").doesNotExist());
  }
}
