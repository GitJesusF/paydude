package com.jesusf.paydude.dto.transactions;

import io.swagger.v3.oas.annotations.media.Schema;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Read model of a transaction, rendered from the requesting user's point of view.
 *
 * <p>A single stored transfer is serialized differently for each party: the
 * {@code TransactionResponseAssembler} sets {@code type} and the {@code counterparty*} fields
 * relative to the caller, so the sender sees {@code SENT} with the recipient as counterparty
 * and the recipient sees {@code RECEIVED} with the sender.
 *
 * @param type                {@code SENT} or {@code RECEIVED}, from the caller's perspective
 * @param amount              the transferred amount
 * @param currency            ISO-4217 code of the transaction
 * @param counterpartyName    display name of the other party
 * @param counterpartyAccount the other party's account number, masked to its last four digits
 * @param description         optional free-text memo
 * @param status              the transaction's {@code TransactionStatus}, as a string
 * @param date                when the transaction was created
 */
@Schema(description = "A transaction as seen by the requesting user (direction and counterparty "
    + "are relative to that user).")
public record TransactionResponse(

    @Schema(description = "Transaction id.", example = "42",
        requiredMode = Schema.RequiredMode.REQUIRED)
    Long id,

    @Schema(description = "Direction relative to the requesting user.", example = "SENT",
        allowableValues = {"SENT", "RECEIVED"}, requiredMode = Schema.RequiredMode.REQUIRED)
    String type,

    @Schema(description = "The transferred amount.", example = "100.0000",
        requiredMode = Schema.RequiredMode.REQUIRED)
    BigDecimal amount,

    @Schema(description = "ISO-4217 currency code.", example = "USD",
        allowableValues = {"USD", "MXN"}, requiredMode = Schema.RequiredMode.REQUIRED)
    String currency,

    @Schema(description = "Display name of the other party.", example = "Maria Garcia",
        requiredMode = Schema.RequiredMode.REQUIRED)
    String counterpartyName,

    @Schema(description = "The other party's account number, masked to its last four digits "
        + "(data minimisation — the caller is not the counterparty).", example = "****1119",
        requiredMode = Schema.RequiredMode.REQUIRED)
    String counterpartyAccount,

    @Schema(description = "Optional free-text memo.", example = "Rent payment", nullable = true)
    String description,

    @Schema(description = "Transaction lifecycle status.", example = "COMPLETED",
        allowableValues = {"PENDING", "PROCESSING", "FROZEN", "COMPLETED", "FAILED", "REVERSED"},
        requiredMode = Schema.RequiredMode.REQUIRED)
    String status,

    @Schema(description = "When the transaction was created (UTC).", example = "2026-04-20T21:00:00Z",
        requiredMode = Schema.RequiredMode.REQUIRED)
    Instant date
) {
}
