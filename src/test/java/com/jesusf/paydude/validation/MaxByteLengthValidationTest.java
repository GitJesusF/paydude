package com.jesusf.paydude.validation;

import com.jesusf.paydude.dto.auth.RegisterRequest;
import com.jesusf.paydude.dto.user.ChangePasswordRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link MaxByteLength}: the validator's UTF-8 byte accounting, and its wiring on the two
 * password fields (RegisterRequest, ChangePasswordRequest) where it caps BCrypt's 72-byte input so
 * a long non-ASCII passphrase fails fast instead of being silently truncated at the hash.
 */
class MaxByteLengthValidationTest {

  private static final String BYTE_MESSAGE = "Password must not exceed 72 bytes when UTF-8 encoded";

  /** Tiny fixture with a small budget so the boundary cases read clearly. */
  private record Holder(@MaxByteLength(5) String field) {}

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

  @Nested
  @DisplayName("byte accounting")
  class ByteAccounting {

    @Test
    @DisplayName("passes at or below the byte budget, fails above it")
    void boundary() {
      assertTrue(validator.validate(new Holder("abc")).isEmpty(), "3 bytes is within 5");
      assertTrue(validator.validate(new Holder("abcde")).isEmpty(), "exactly 5 bytes is allowed");
      assertFalse(validator.validate(new Holder("abcdef")).isEmpty(), "6 bytes exceeds 5");
    }

    @Test
    @DisplayName("counts UTF-8 bytes, not characters")
    void countsBytesNotChars() {
      // "héllo" is 5 chars but 6 bytes (é = 2 bytes in UTF-8) — exactly the case @Size(max = 5)
      // would let through, and the reason this constraint exists.
      assertFalse(validator.validate(new Holder("héllo")).isEmpty(),
          "5 chars but 6 bytes must fail a 5-byte budget");
    }

    @Test
    @DisplayName("null passes — presence is a separate concern")
    void nullIsValid() {
      assertTrue(validator.validate(new Holder(null)).isEmpty());
    }

    @Test
    @DisplayName("interpolates the byte budget into the default message")
    void defaultMessage() {
      Set<ConstraintViolation<Holder>> violations = validator.validate(new Holder("abcdef"));
      assertEquals("must be at most 5 bytes when UTF-8 encoded",
          violations.iterator().next().getMessage());
    }
  }

  @Nested
  @DisplayName("password fields cap at 72 UTF-8 bytes")
  class PasswordFields {

    private static final String CYRILLIC = "ж"; // U+0436 — 2 bytes in UTF-8, 1 char

    @Test
    @DisplayName("a 64-character ASCII password (64 bytes) is accepted")
    void asciiWithinBudget() {
      RegisterRequest request = register("a".repeat(64));
      assertFalse(hasByteViolation(validator.validate(request), "password"),
          "64 ASCII bytes is within 72");
    }

    @Test
    @DisplayName("a 40-character Cyrillic password (80 bytes) is rejected on register")
    void multibyteOverBudgetRegister() {
      // 40 chars ≤ 64 (passes @Size) but 80 bytes > 72 — the exact gap @Size alone left open.
      RegisterRequest request = register(CYRILLIC.repeat(40));
      assertTrue(hasByteViolation(validator.validate(request), "password"),
          "80 UTF-8 bytes under 64 chars must be rejected");
    }

    @Test
    @DisplayName("exactly 72 bytes is accepted")
    void exactlyAtBudget() {
      RegisterRequest request = register(CYRILLIC.repeat(36)); // 36 × 2 = 72 bytes
      assertFalse(hasByteViolation(validator.validate(request), "password"),
          "exactly 72 bytes is allowed");
    }

    @Test
    @DisplayName("the same cap applies to a password change")
    void multibyteOverBudgetChangePassword() {
      ChangePasswordRequest request = new ChangePasswordRequest("Curr3ntP@ss", CYRILLIC.repeat(40));
      assertTrue(hasByteViolation(validator.validate(request), "newPassword"),
          "newPassword must enforce the same 72-byte cap");
    }

    private RegisterRequest register(String password) {
      return new RegisterRequest("Maria", "Garcia", "maria@example.com", password);
    }

    private boolean hasByteViolation(Set<? extends ConstraintViolation<?>> violations, String property) {
      return violations.stream().anyMatch(v ->
          v.getPropertyPath().toString().equals(property) && v.getMessage().equals(BYTE_MESSAGE));
    }
  }
}
