package com.jesusf.paydude.validation;

import com.jesusf.paydude.dto.idempotent.AccountOperationRequest;
import com.jesusf.paydude.dto.idempotent.TransferRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Bean-validation coverage for money-moving request DTO boundaries. */
class FinancialRequestValidationTest {

  private static final String VALID_SOURCE = "4520000000000003";
  private static final String VALID_TARGET = "4521111111111115";
  private static final String INVALID_LUHN = "4520000000000000";

  private static ValidatorFactory factory;
  private static Validator validator;

  @BeforeAll
  static void setUp() {
    factory = Validation.buildDefaultValidatorFactory();
    validator = factory.getValidator();
  }

  @AfterAll
  static void tearDown() {
    factory.close();
  }

  @Test
  @DisplayName("Transfer account numbers must be 16-digit Luhn-valid values")
  void transferAccountNumbersMustBeWellFormed() {
    TransferRequest request = new TransferRequest(
        INVALID_LUHN, VALID_TARGET, new BigDecimal("10.00"), "USD", "rent");

    Set<ConstraintViolation<TransferRequest>> violations = validator.validate(request);

    assertTrue(hasViolation(violations, "sourceAccountNumber"),
        "sourceAccountNumber should reject a 16-digit value with a bad Luhn check digit");
  }

  @Test
  @DisplayName("Transfer description is capped at the DB width")
  void transferDescriptionIsCapped() {
    TransferRequest request = new TransferRequest(
        VALID_SOURCE, VALID_TARGET, new BigDecimal("10.00"), "USD", "x".repeat(256));

    assertTrue(hasViolation(validator.validate(request), "description"));
  }

  @Test
  @DisplayName("Transfer amount must fit NUMERIC(19,4)")
  void transferAmountMustFitDatabasePrecision() {
    TransferRequest request = new TransferRequest(
        VALID_SOURCE, VALID_TARGET, new BigDecimal("1000000000000000.0000"), "USD", null);

    assertTrue(hasViolation(validator.validate(request), "amount"));
  }

  @Test
  @DisplayName("Account operation amount must fit NUMERIC(19,4)")
  void accountOperationAmountMustFitDatabasePrecision() {
    AccountOperationRequest request = new AccountOperationRequest(
        new BigDecimal("10.00001"), "memo");

    assertTrue(hasViolation(validator.validate(request), "amount"));
  }

  @Test
  @DisplayName("Valid financial requests pass the added boundary checks")
  void validRequestsPass() {
    TransferRequest transfer = new TransferRequest(
        VALID_SOURCE, VALID_TARGET, new BigDecimal("10.0000"), "USD", "x".repeat(255));
    AccountOperationRequest operation = new AccountOperationRequest(new BigDecimal("10.0000"), "memo");

    assertFalse(hasViolation(validator.validate(transfer), "sourceAccountNumber"));
    assertFalse(hasViolation(validator.validate(transfer), "targetAccountNumber"));
    assertFalse(hasViolation(validator.validate(transfer), "amount"));
    assertFalse(hasViolation(validator.validate(transfer), "description"));
    assertFalse(hasViolation(validator.validate(operation), "amount"));
  }

  private static boolean hasViolation(Set<? extends ConstraintViolation<?>> violations, String property) {
    return violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals(property));
  }
}
