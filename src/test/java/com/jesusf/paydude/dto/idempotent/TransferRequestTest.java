package com.jesusf.paydude.dto.idempotent;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for the cross-field invariants enforced inside {@link TransferRequest}'s compact
 * constructor. Field-level validation (Jakarta annotations) is exercised end-to-end through the
 * controller tests; here we only cover what the type itself rejects at construction time.
 *
 * <p>The split of responsibilities: the compact constructor enforces only what genuinely needs
 * two components at once (source != target) — it guarantees no such instance can ever exist,
 * whether built directly or deserialized by Jackson. Everything field-level stays with Jakarta,
 * which runs after construction during {@code @RequestBody} binding.
 */
class TransferRequestTest {

  @Test
  @DisplayName("Reject construction when source and target accounts are equal")
  void shouldRejectSameSourceAndTarget() {
    // A self-transfer has no financial meaning and would produce a net-zero debit+credit with
    // two audit rows; the constructor rejects it at the boundary.
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        new TransferRequest(
            "MY-ACC-001",
            "MY-ACC-001",
            new BigDecimal("10.00"),
            "USD",
            "Self"
        )
    );

    assertEquals("Source and target accounts must differ", ex.getMessage());
  }

  @Test
  @DisplayName("Allow construction when source and target accounts differ")
  void shouldAcceptDistinctAccounts() {
    // Inverse sanity check: without it, the assertThrows above would pass even if the
    // constructor always threw.
    assertDoesNotThrow(() ->
        new TransferRequest(
            "MY-ACC-001",
            "MY-ACC-002",
            new BigDecimal("10.00"),
            "USD",
            "Rent"
        )
    );
  }

  @Test
  @DisplayName("Allow construction when one of the account fields is null (Jakarta @NotBlank handles it later)")
  void shouldNotFailOnNullAccountFields() {
    // The constructor must not duplicate Jakarta's field-level checks: throwing on null here
    // would pre-empt deserialization and rob the client of the per-field validation
    // ProblemDetail it would otherwise receive.
    assertDoesNotThrow(() ->
        new TransferRequest(
            null,
            "MY-ACC-002",
            new BigDecimal("10.00"),
            "USD",
            null
        )
    );
    assertDoesNotThrow(() ->
        new TransferRequest(
            "MY-ACC-001",
            null,
            new BigDecimal("10.00"),
            "USD",
            null
        )
    );
  }
}
