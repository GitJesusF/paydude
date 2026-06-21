package com.jesusf.paydude.dto.idempotent;

import com.jesusf.paydude.validation.AccountNumber;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Digits;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.math.BigDecimal;

/**
 * Body of {@code POST /v1/transactions/transfer} — a money movement between two accounts.
 *
 * @param sourceAccountNumber the account funds are debited from; must belong to the caller
 * @param targetAccountNumber the account funds are credited to
 * @param amount              the amount to transfer
 * @param currency            the transfer currency
 * @param description         an optional free-text memo, excluded from the idempotency fingerprint
 */
@Schema(description = "Transfer instruction: move funds from the caller's account to another account.")
public record TransferRequest(

    @Schema(description = "Source account number — must belong to the authenticated user.",
        example = "4520000000000001", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Source account number is required")
    @AccountNumber
    String sourceAccountNumber,

    @Schema(description = "Target (destination) account number.",
        example = "4521111111111119", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Target account number is required")
    @AccountNumber
    String targetAccountNumber,

    @Schema(description = "Amount to transfer; must be at least 0.01.",
        example = "100.00", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotNull(message = "Amount is required")
    @DecimalMin(value = "0.01", message = "Minimum transfer amount is 0.01")
    @Digits(integer = 15, fraction = 4, message = "Amount must fit NUMERIC(19,4)")
    BigDecimal amount,

    @Schema(description = "ISO-4217 currency code; must match both accounts.",
        example = "USD", allowableValues = {"USD", "MXN"},
        requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Currency is required")
    @Pattern(regexp = "USD|MXN", message = "Currency must be one of: USD, MXN")
    String currency,

    @Schema(description = "Optional free-text memo. Excluded from the idempotency fingerprint, "
        + "so changing it on a retry does not create a conflict.",
        example = "Rent payment", maxLength = 255, requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    @Size(max = 255, message = "Description must be at most 255 chars")
    String description
) implements IdempotentRequest {

  /**
   * Cross-field invariant enforced at construction time. A transfer to the same account is not a
   * business-rule conflict — it is a structurally invalid request, and the right place to reject it
   * is the type itself, before any service or transaction is ever entered.
   *
   * <p>The null-guards exist because Jakarta {@code @NotBlank} only runs after the canonical
   * constructor returns, so during deserialization either field can transiently be {@code null}.
   * This check fires only when both have arrived intact.
   */
  public TransferRequest {
    if (sourceAccountNumber != null && targetAccountNumber != null && sourceAccountNumber.equals(targetAccountNumber)) {
      throw new IllegalArgumentException("Source and target accounts must differ");
    }
  }
}
