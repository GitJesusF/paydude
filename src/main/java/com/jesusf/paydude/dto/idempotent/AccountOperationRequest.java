package com.jesusf.paydude.dto.idempotent;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Digits;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.math.BigDecimal;

/**
 * Body of the idempotent single-account operations {@code POST /v1/accounts/deposit}
 * and {@code POST /v1/accounts/withdraw}.
 *
 * <p>One DTO serves both endpoints; the operation is distinguished by the route, and that route
 * name is folded into the idempotency-key scope so a key used for a deposit can never replay a
 * withdrawal. As an {@link IdempotentRequest} it is accepted by
 * {@code IdempotencyKeyService.reserveKey}; {@code description} is excluded from the request hash
 * via its canonical-JSON mix-in.
 *
 * @param amount      the amount to move; strictly positive (minimum {@code 0.01})
 * @param description optional free-text memo, capped at 255 characters and ignored by the
 *                    idempotency fingerprint
 */
@Schema(description = "Amount (and optional memo) for a deposit or withdrawal.")
public record AccountOperationRequest(

    @Schema(description = "Amount to move; must be at least 0.01.", example = "150.00",
        requiredMode = Schema.RequiredMode.REQUIRED)
    @NotNull(message = "Amount is required")
    @DecimalMin(value = "0.01", message = "Minimum amount is 0.01")
    @Digits(integer = 15, fraction = 4, message = "Amount must fit NUMERIC(19,4)")
    BigDecimal amount,

    @Schema(description = "Optional free-text memo (max 255 characters). Excluded from the "
        + "idempotency fingerprint.", example = "ATM deposit", maxLength = 255,
        requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    @Size(max = 255, message = "Description must be at most 255 chars")
    String description
) implements IdempotentRequest {
}
