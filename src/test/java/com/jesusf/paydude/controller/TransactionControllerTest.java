package com.jesusf.paydude.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jesusf.paydude.support.WithMockSecurityUser;
import com.jesusf.paydude.dto.idempotent.TransferRequest;
import com.jesusf.paydude.dto.transactions.TransactionResponse;
import com.jesusf.paydude.exception.RateLimitExceededException;
import com.jesusf.paydude.security.CustomUserDetailsService;
import com.jesusf.paydude.security.JwtService;
import com.jesusf.paydude.security.ratelimit.AuthRateLimiter;
import com.jesusf.paydude.security.ratelimit.WriteRateLimiter;
import com.jesusf.paydude.service.TransactionService;
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
 * Web-layer tests for {@link TransactionController}.
 *
 * <p>Pins four contracts: (1) {@code POST /v1/transactions/transfer} delegates to
 * {@link TransactionService#transfer} only after the per-user write limiter allows the request,
 * returning the response DTO as JSON; (2) an exhausted write bucket returns 429 before any service
 * call; (3) the same endpoint rejects requests with a missing or malformed key as 400 before any
 * service call; (4) {@code GET /v1/transactions} maps the
 * {@code Page<T>} returned by the service into a framework-agnostic {@code PagedResponse<T>}
 * envelope before serialization.
 */
@WebMvcTest(controllers = TransactionController.class)
@AutoConfigureMockMvc(addFilters = false)
class TransactionControllerTest {

  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper objectMapper;

  @MockitoBean private TransactionService transactionService;
  @MockitoBean private JwtService jwtService;
  @MockitoBean private CustomUserDetailsService userDetailsService;
  // The slice scans all Filter @Components, so IpRateLimitFilter is constructed (though never
  // run with addFilters=false) and its AuthRateLimiter dependency must be satisfied.
  @MockitoBean private AuthRateLimiter authRateLimiter;
  // Direct dependency of TransactionController (per-user throttle on transfer). Its
  // enforceWriteByUser is void, so Mockito's default (do nothing) lets the happy path through;
  // the throttling test uses doThrow to simulate a drained bucket.
  @MockitoBean private WriteRateLimiter writeRateLimiter;

  // Matches @WithMockSecurityUser's default id.
  private static final Long MOCK_USER_ID = 1L;
  private static final String SOURCE_ACCOUNT = "4520000000000003";
  private static final String TARGET_ACCOUNT = "4521111111111115";

  @Test
  @DisplayName("POST /transactions/transfer - Should succeed with valid data and Idempotency Key")
  @WithMockSecurityUser
  void shouldTransferSuccessfully() throws Exception {
    // The Idempotency-Key header is @Pattern-validated as a UUID before the handler body runs.
    String idempotencyKey = "550e8400-e29b-41d4-a716-446655440000";

    TransferRequest request = new TransferRequest(
        SOURCE_ACCOUNT, TARGET_ACCOUNT, new BigDecimal("50.00"), "USD", "Rent"
    );

    TransactionResponse mockResponse = new TransactionResponse(
        100L, "SENT", new BigDecimal("50.00"), "USD", "Target", TARGET_ACCOUNT, "Rent", "COMPLETED", Instant.now()
    );

    when(transactionService.transfer(eq(MOCK_USER_ID), any(TransferRequest.class), eq(idempotencyKey)))
        .thenReturn(mockResponse);

    mockMvc.perform(post("/v1/transactions/transfer")
            .header("Idempotency-Key", idempotencyKey)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isOk())
        .andExpect(jsonPath("$.status").value("COMPLETED"))
        .andExpect(jsonPath("$.amount").value(50.0));

    verify(writeRateLimiter).enforceWriteByUser(eq(MOCK_USER_ID), anyString());
  }

  @Test
  @DisplayName("POST /transactions/transfer - Should fail 429 when the per-user write throttle is exhausted")
  @WithMockSecurityUser
  void shouldRejectTransferWhenWriteRateLimited() throws Exception {
    // The key is a valid UUID on purpose: the 429 must come from the drained bucket, not from
    // header validation (which is evaluated first).
    String idempotencyKey = "550e8400-e29b-41d4-a716-446655440000";
    TransferRequest request = new TransferRequest(
        SOURCE_ACCOUNT, TARGET_ACCOUNT, new BigDecimal("50.00"), "USD", "Rent"
    );

    doThrow(new RateLimitExceededException("Too many transfer operations.", 60L))
        .when(writeRateLimiter).enforceWriteByUser(eq(MOCK_USER_ID), anyString());

    mockMvc.perform(post("/v1/transactions/transfer")
            .header("Idempotency-Key", idempotencyKey)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isTooManyRequests())
        .andExpect(header().exists("Retry-After"));

    // The throttle cuts the flow before any business work.
    verify(transactionService, never()).transfer(any(), any(), any());
  }

  @Test
  @DisplayName("POST /transactions/transfer - Should fail 400 if Idempotency Key is missing")
  @WithMockSecurityUser
  void shouldFailWithoutIdempotencyKey() throws Exception {
    // @RequestHeader without a default → MissingRequestHeaderException → 400; the service is
    // never invoked.
    TransferRequest request = new TransferRequest(SOURCE_ACCOUNT, TARGET_ACCOUNT, BigDecimal.TEN, "USD", "Desc");

    mockMvc.perform(post("/v1/transactions/transfer")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isBadRequest());

    verify(transactionService, never()).transfer(any(), any(), any());
  }

  @Test
  @DisplayName("POST /transactions/transfer - Should fail 400 if Idempotency Key is not a valid UUID")
  @WithMockSecurityUser
  void shouldFailWithMalformedIdempotencyKey() throws Exception {
    // Header present but not a UUID: the @Pattern rejects it with ConstraintViolationException,
    // translated to the same 400.
    TransferRequest request = new TransferRequest(SOURCE_ACCOUNT, TARGET_ACCOUNT, BigDecimal.TEN, "USD", "Desc");

    mockMvc.perform(post("/v1/transactions/transfer")
            .header("Idempotency-Key", "not-a-uuid")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isBadRequest());

    verify(transactionService, never()).transfer(any(), any(), any());
  }

  @Test
  @DisplayName("GET /transactions - Should map Page to PagedResponse envelope before serializing")
  @WithMockSecurityUser
  void shouldReturnTransactionHistory() throws Exception {
    // PageImpl's JSON is not a stable contract (Boot 3.2+ warns on serializing it); the
    // controller maps to the six-field PagedResponse envelope instead.
    TransactionResponse tx = new TransactionResponse(
        1L, "SENT", BigDecimal.TEN, "USD", "Bob", "ACC", "Desc", "COMPLETED", Instant.now()
    );
    Page<TransactionResponse> mockPage = new PageImpl<>(List.of(tx), PageRequest.of(0, 10), 1);

    when(transactionService.getMyTransactions(eq(MOCK_USER_ID), any(Pageable.class)))
        .thenReturn(mockPage);

    mockMvc.perform(get("/v1/transactions")
            .param("page", "0")
            .param("size", "10"))

        .andExpect(status().isOk())
        .andExpect(jsonPath("$.content[0].type").value("SENT"))
        // All six envelope fields are versioned /v1 contract — a change here would be breaking.
        .andExpect(jsonPath("$.page").value(0))
        .andExpect(jsonPath("$.size").value(10))
        .andExpect(jsonPath("$.totalElements").value(1))
        .andExpect(jsonPath("$.totalPages").value(1))
        .andExpect(jsonPath("$.hasNext").value(false))
        // Internal PageImpl fields must not leak; reverting the mapping would trip these.
        .andExpect(jsonPath("$.pageable").doesNotExist())
        .andExpect(jsonPath("$.sort").doesNotExist())
        .andExpect(jsonPath("$.empty").doesNotExist());
  }
}
