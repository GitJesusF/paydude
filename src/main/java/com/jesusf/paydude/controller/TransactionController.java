package com.jesusf.paydude.controller;

import com.jesusf.paydude.config.web.ApiV1;
import com.jesusf.paydude.dto.PagedResponse;
import com.jesusf.paydude.dto.transactions.TransactionResponse;
import com.jesusf.paydude.dto.idempotent.TransferRequest;
import com.jesusf.paydude.security.SecurityUser;
import com.jesusf.paydude.security.ratelimit.WriteRateLimiter;
import com.jesusf.paydude.service.TransactionService;
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
 * HTTP endpoints for executing transfers and reading transaction history. Mounted under
 * {@code /v1/transactions}.
 *
 * <p>A transfer requires a UUID {@code Idempotency-Key} header — validated for shape here and
 * used by the service layer to make the money movement safe to retry. History is returned as a
 * {@link PagedResponse} envelope, and each row is rendered from the requesting user's
 * perspective ({@code SENT} vs {@code RECEIVED}).
 *
 * <p>Every error response uses the RFC 9457 {@code application/problem+json} shape
 * ({@link ProblemDetail}).
 */
@RestController
@RequestMapping("/transactions")
@ApiV1
@RequiredArgsConstructor
@Validated
@Tag(name = "Transactions", description = "Transfer execution and history endpoints")
@SecurityRequirement(name = "bearerAuth")
public class TransactionController {

  private final TransactionService transactionService;
  private final WriteRateLimiter writeRateLimiter;

  /**
   * Executes a transfer from the authenticated user's account to another account.
   *
   * @param currentUser    the authenticated user (the sender)
   * @param idempotencyKey UUID-v4 {@code Idempotency-Key} header; a retry with the same key
   *                       replays the original result instead of transferring twice
   * @param request        the transfer details (target account, amount, currency, memo)
   * @return {@code 200 OK} with the resulting transaction, from the sender's perspective
   */
  @Operation(
      summary = "Execute a transfer",
      description = "Moves funds from the authenticated user's account to another account. "
          + "Requires an Idempotency-Key header to safely retry without duplicating the operation."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Transfer completed (or replayed)",
          content = @Content(schema = @Schema(implementation = TransactionResponse.class))),
      @ApiResponse(responseCode = "400", description = "Invalid request body or Idempotency-Key header",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "404", description = "Source or target account not found",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "409", description = "Insufficient funds, currency mismatch, "
          + "account not active, source account not owned by the caller, or the idempotency key "
          + "was reused with a different request",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "429", description = "Too many write operations for this account",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @PostMapping("/transfer")
  public ResponseEntity<TransactionResponse> transfer(
      @AuthenticationPrincipal SecurityUser currentUser,

      @Parameter(description = "Unique idempotency token for the request (UUID v4)", required = true)
      @RequestHeader("Idempotency-Key")
      @IdempotencyKey
      String idempotencyKey,

      @Valid @RequestBody TransferRequest request
  ) {
    writeRateLimiter.enforceWriteByUser(currentUser.id(),
        "Too many transfer operations. Please slow down and try again shortly.");
    return ResponseEntity.ok(
        transactionService.transfer(currentUser.id(), request, idempotencyKey)
    );
  }

  /**
   * Returns a page of the user's transaction history, newest first.
   *
   * @param currentUser the authenticated user
   * @param pageable    page index, size and sort (defaults: size 20, by {@code createdAt} desc)
   * @return {@code 200 OK} with a {@link PagedResponse} of transactions
   */
  @Operation(summary = "Get transaction history",
      description = "Returns a paginated PagedResponse envelope of transactions, newest first.")
  @ApiResponses({
      @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "404", description = "No account exists for the user",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @GetMapping
  public ResponseEntity<PagedResponse<TransactionResponse>> getMyTransactions(
      @AuthenticationPrincipal SecurityUser currentUser,
      @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable
  ) {
    return ResponseEntity.ok(
        PagedResponse.from(transactionService.getMyTransactions(currentUser.id(), pageable))
    );
  }
}
