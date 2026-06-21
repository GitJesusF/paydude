package com.jesusf.paydude.util;

import java.security.SecureRandom;

/**
 * Generates 16-digit bank account numbers with a Luhn check digit.
 *
 * <p>Layout: a fixed 3-digit bank prefix + 12 random digits + 1 Luhn check digit. The Luhn digit
 * makes accidental single-digit typos detectable without a database round-trip. Randomness comes
 * from {@link SecureRandom} so account numbers are not predictable; the rare collision is handled
 * by the caller ({@code AccountServiceImpl.createDefaultAccount}), which checks
 * {@code AccountRepository.existsByAccountNumber} before inserting and regenerates on a hit.
 *
 * <p>This is a stateless utility — hence {@code final} with a private constructor.
 */
public final class AccountNumberGenerator {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final String BANK_PREFIX = "452";

  private AccountNumberGenerator() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }

  /**
   * Generates a 16-digit account number.
   *
   * <p>Format: prefix (3) + random digits (12) + Luhn check digit (1).
   *
   * @return a fresh, Luhn-valid 16-digit account number
   */
  public static String generate() {
    StringBuilder builder = new StringBuilder(BANK_PREFIX);

    // Append 12 cryptographically strong random digits.
    for (int i = 0; i < 12; i++) {
      builder.append(RANDOM.nextInt(10));
    }

    String partialAccount = builder.toString();
    int checkDigit = Luhn.checkDigit(partialAccount);

    return partialAccount + checkDigit;
  }
}
