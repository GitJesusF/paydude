package com.jesusf.paydude.dto.account;

import io.swagger.v3.oas.annotations.media.Schema;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Read model of a single balance-change audit row, returned in the paginated
 * {@code GET /v1/accounts/me/history} response.
 *
 * <p>Audit rows are immutable: one is written for every operation that moves money, capturing
 * the balance on both sides of the change.
 *
 * @param id            audit row id
 * @param action        the {@code AuditAction} that produced the change, as a string
 * @param amount        the amount moved
 * @param balanceBefore account balance immediately before the operation
 * @param balanceAfter  account balance immediately after the operation
 * @param transactionId the related transfer, or {@code null} for a deposit or withdrawal
 * @param createdAt     when the operation was recorded
 */
@Schema(description = "An immutable record of a single balance change on an account.")
public record AccountAuditResponse(

    @Schema(description = "Audit row id.", example = "5012",
        requiredMode = Schema.RequiredMode.REQUIRED)
    Long id,

    @Schema(description = "The kind of balance change.", example = "TRANSFER_OUT",
        allowableValues = {"DEPOSIT", "WITHDRAW", "TRANSFER_IN", "TRANSFER_OUT"},
        requiredMode = Schema.RequiredMode.REQUIRED)
    String action,

    @Schema(description = "The amount moved.", example = "100.0000",
        requiredMode = Schema.RequiredMode.REQUIRED)
    BigDecimal amount,

    @Schema(description = "Account balance immediately before the operation.", example = "1350.75",
        requiredMode = Schema.RequiredMode.REQUIRED)
    BigDecimal balanceBefore,

    @Schema(description = "Account balance immediately after the operation.", example = "1250.75",
        requiredMode = Schema.RequiredMode.REQUIRED)
    BigDecimal balanceAfter,

    @Schema(description = "Id of the related transfer; null for a deposit or withdrawal.",
        example = "42", nullable = true)
    Long transactionId,

    @Schema(description = "When the operation was recorded (UTC).", example = "2026-04-20T21:00:00Z",
        requiredMode = Schema.RequiredMode.REQUIRED)
    Instant createdAt
) {
}
