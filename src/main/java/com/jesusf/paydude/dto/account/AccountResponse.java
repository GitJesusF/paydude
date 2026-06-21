package com.jesusf.paydude.dto.account;

import io.swagger.v3.oas.annotations.media.Schema;

import java.math.BigDecimal;

/**
 * Read model of a bank account, returned by {@code GET /v1/accounts/me} and as the cached
 * response body of an idempotent deposit or withdrawal.
 *
 * @param accountNumber the 16-digit Luhn-checked account number
 * @param balance       current available balance
 * @param currency      ISO-4217 code of the account ({@code USD} or {@code MXN})
 * @param status        the account's {@code AccountStatus}, as a string
 */
@Schema(description = "A bank account: number, balance, currency and status.")
public record AccountResponse(

    @Schema(description = "16-digit Luhn-checked account number.", example = "4520000000000001",
        requiredMode = Schema.RequiredMode.REQUIRED)
    String accountNumber,

    @Schema(description = "Current available balance.", example = "1250.75",
        requiredMode = Schema.RequiredMode.REQUIRED)
    BigDecimal balance,

    @Schema(description = "ISO-4217 currency code of the account.", example = "USD",
        allowableValues = {"USD", "MXN"}, requiredMode = Schema.RequiredMode.REQUIRED)
    String currency,

    @Schema(description = "Account lifecycle status.", example = "ACTIVE",
        allowableValues = {"ACTIVE", "PENDING", "FROZEN", "CLOSED"},
        requiredMode = Schema.RequiredMode.REQUIRED)
    String status
) {
}
