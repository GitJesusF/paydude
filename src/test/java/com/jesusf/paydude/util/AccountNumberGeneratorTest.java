package com.jesusf.paydude.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link AccountNumberGenerator}.
 *
 * <p>The generator produces 16-digit account numbers that must (a) be unique enough across calls
 * to make collisions astronomically unlikely, and (b) pass the Luhn checksum so downstream systems
 * — payment networks, audit tools — accept them as well-formed. A regression in either property
 * would silently corrupt every newly-created account, so the contract is worth pinning directly.
 */
class AccountNumberGeneratorTest {

  @Test
  @DisplayName("generates a 16-digit numeric account number")
  void generatesSixteenDigits() {
    // Contract format: 3-digit bank prefix ("452") + 12 random digits + 1 Luhn check digit.
    String number = AccountNumberGenerator.generate();

    assertEquals(16, number.length());
    assertTrue(number.matches("\\d{16}"), "Expected 16 digits, got: " + number);
  }

  @Test
  @DisplayName("starts with the bank prefix 452")
  void startsWithBankPrefix() {
    // Changing the issuer prefix would require migrating every issued account; pin it.
    assertTrue(AccountNumberGenerator.generate().startsWith("452"));
  }

  @RepeatedTest(50)
  @DisplayName("the Luhn check digit is always valid")
  void luhnCheckDigitIsValid() {
    // Repeated because the input is SecureRandom-driven: a single run could pass by luck on an
    // input that doesn't expose the bug.
    String number = AccountNumberGenerator.generate();
    assertTrue(passesLuhn(number), "Generated number failed Luhn validation: " + number);
  }

  @Test
  @DisplayName("consecutive invocations produce different numbers")
  void consecutiveCallsAreUnique() {
    // Collision space is 10^12; a failure here almost certainly means a regression (seeded
    // Random, accidental caching), not chance.
    String first = AccountNumberGenerator.generate();
    String second = AccountNumberGenerator.generate();
    assertNotEquals(first, second);
  }

  // Reference Luhn validator, independent of the production Luhn class — a test oracle. Two
  // independent implementations must agree; validating the generator against its own helper
  // would let a symmetric bug (the same wrong constant on both sides) pass unnoticed.
  private static boolean passesLuhn(String number) {
    int sum = 0;
    boolean alternate = false;
    for (int i = number.length() - 1; i >= 0; i--) {
      int n = Character.digit(number.charAt(i), 10);
      if (alternate) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alternate = !alternate;
    }
    return sum % 10 == 0;
  }
}
