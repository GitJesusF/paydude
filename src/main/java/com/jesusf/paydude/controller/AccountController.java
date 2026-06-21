package com.jesusf.paydude.controller;

import com.jesusf.paydude.config.web.ApiV1;
import com.jesusf.paydude.dto.PagedResponse;
import com.jesusf.paydude.dto.account.AccountAuditResponse;
import com.jesusf.paydude.dto.idempotent.AccountOperationRequest;
import com.jesusf.paydude.dto.account.AccountResponse;
import com.jesusf.paydude.security.SecurityUser;
import com.jesusf.paydude.security.ratelimit.WriteRateLimiter;
import com.jesusf.paydude.service.AccountService;
import com.jesusf.paydude.validation.IdempotencyKey;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP endpoints for a user's own account: balance lookup, single-account money operations,
 * and balance-change history. Mounted under {@code /v1/accounts}; every endpoint operates on
 * the authenticated caller's account only.
 *
 * <p>Deposits and withdrawals are idempotent — each requires a UUID {@code Idempotency-Key}
 * header. The header shape is validated here; the service layer uses it to deduplicate retries.
 * History is returned as a {@link PagedResponse} envelope rather than a raw Spring Data
 * {@code Page}, keeping the JSON contract stable.
 *
 * <p>Every error response uses the RFC 9457 {@code application/problem+json} shape
 * ({@link ProblemDetail}).
 */
@RestController
@RequestMapping("/accounts")
@ApiV1
@RequiredArgsConstructor
@Validated
@Tag(name = "Accounts", description = "Account balance and history management")
@SecurityRequirement(name = "bearerAuth")
public class AccountController {

  private final AccountService accountService;
  private final WriteRateLimiter writeRateLimiter;

  /**
   * Returns the authenticated user's account — number, balance, currency and status.
   *
   * @param principal the authenticated user
   * @return {@code 200 OK} with the account details
   */
  @Operation(summary = "Get my account details")
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Account returned",
          content = @Content(schema = @Schema(implementation = AccountResponse.class))),
      @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "404", description = "No account exists for the user",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @GetMapping("/me")
  public ResponseEntity<AccountResponse> getMyAccount(
      @AuthenticationPrincipal SecurityUser principal
  ) {
    return ResponseEntity.ok(accountService.getMyAccount(principal.id()));
  }

  /**
   * Deposits funds into the authenticated user's account.
   *
   * @param principal      the authenticated user
   * @param idempotencyKey UUID-v4 {@code Idempotency-Key} header; a retry with the same key
   *                       replays the original result instead of depositing twice
   * @param request        the amount (and optional memo) to deposit
   * @return {@code 200 OK} with the account state after the deposit
   */
  @Operation(summary = "Deposit funds into my account")
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Deposit applied (or replayed)",
          content = @Content(schema = @Schema(implementation = AccountResponse.class))),
      @ApiResponse(responseCode = "400", description = "Invalid request body or Idempotency-Key header",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "404", description = "No account exists for the user",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "409", description = "Account not active, or the idempotency "
          + "key was reused with a different request",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "429", description = "Too many write operations for this account",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @PostMapping("/deposit")
  public ResponseEntity<AccountResponse> deposit(
      @AuthenticationPrincipal SecurityUser principal,

      @Parameter(description = "Unique idempotency token for the request (UUID v4)", required = true)
      @RequestHeader("Idempotency-Key")
      @IdempotencyKey
      String idempotencyKey,

      @Valid @RequestBody AccountOperationRequest request
  ) {
    writeRateLimiter.enforceWriteByUser(principal.id(),
        "Too many account operations. Please slow down and try again shortly.");
    return ResponseEntity.ok(accountService.deposit(principal.id(), request, idempotencyKey));
  }

  /**
   * Withdraws funds from the authenticated user's account.
   *
   * @param principal      the authenticated user
   * @param idempotencyKey UUID-v4 {@code Idempotency-Key} header; a retry with the same key
   *                       replays the original result instead of withdrawing twice
   * @param request        the amount (and optional memo) to withdraw
   * @return {@code 200 OK} with the account state after the withdrawal
   */
  @Operation(summary = "Withdraw funds from my account")
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Withdrawal applied (or replayed)",
          content = @Content(schema = @Schema(implementation = AccountResponse.class))),
      @ApiResponse(responseCode = "400", description = "Invalid request body or Idempotency-Key header",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "404", description = "No account exists for the user",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "409", description = "Insufficient funds, account not active, "
          + "or the idempotency key was reused with a different request",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "429", description = "Too many write operations for this account",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @PostMapping("/withdraw")
  public ResponseEntity<AccountResponse> withdraw(
      @AuthenticationPrincipal SecurityUser principal,

      @Parameter(description = "Unique idempotency token for the request (UUID v4)", required = true)
      @RequestHeader("Idempotency-Key")
      @IdempotencyKey
      String idempotencyKey,

      @Valid @RequestBody AccountOperationRequest request
  ) {
    writeRateLimiter.enforceWriteByUser(principal.id(),
        "Too many account operations. Please slow down and try again shortly.");
    return ResponseEntity.ok(accountService.withdraw(principal.id(), request, idempotencyKey));
  }

  /**
   * Returns a page of the account's balance-change audit history, newest first.
   *
   * @param principal the authenticated user
   * @param pageable  page index, size and sort (defaults: size 20, by {@code createdAt} desc)
   * @return {@code 200 OK} with a {@link PagedResponse} of audit rows
   */
  @Operation(summary = "Get my account audit history",
      description = "Returns a paginated PagedResponse envelope of audit rows, newest first.")
  @ApiResponses({
      @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "404", description = "No account exists for the user",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @GetMapping("/me/history")
  public ResponseEntity<PagedResponse<AccountAuditResponse>> getMyAuditHistory(
      @AuthenticationPrincipal SecurityUser principal,
      @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable
  ) {
    return ResponseEntity.ok(
        PagedResponse.from(accountService.getMyAuditHistory(principal.id(), pageable))
    );
  }
}
