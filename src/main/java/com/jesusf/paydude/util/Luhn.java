package com.jesusf.paydude.util;

/**
 * The Luhn algorithm (mod-10 checksum, ISO/IEC 7812-1) shared by the two sides of PayDude's
 * account-number contract: {@link AccountNumberGenerator} appends a check digit, and
 * {@code AccountNumberValidator} verifies one. Both reduce to the same right-to-left weighted digit
 * sum — kept here once so the generate and validate paths can never drift apart.
 *
 * <p>Inputs are assumed to be non-null strings of ASCII decimal digits; callers guarantee that
 * (the generator builds the string itself, the validator checks length and digit-only first).
 */
public final class Luhn {

  private Luhn() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }

  /**
   * Computes the Luhn check digit for {@code partial} — the digits it will be appended to. Doubling
   * starts on the rightmost digit of {@code partial}, because appending the check digit shifts every
   * existing digit one position to the left.
   *
   * @param partial the digit string the check digit will be appended to
   * @return the check digit (0–9) that makes {@code partial + checkDigit} Luhn-valid
   */
  public static int checkDigit(String partial) {
    return (10 - weightedSum(partial, true) % 10) % 10;
  }

  /**
   * Verifies a number that already carries its trailing check digit.
   *
   * @param digits a full numeric string including its check digit
   * @return {@code true} if {@code digits} satisfies the Luhn checksum
   */
  public static boolean isValid(String digits) {
    return weightedSum(digits, false) % 10 == 0;
  }

  /**
   * Right-to-left Luhn weighted sum. Every second digit is doubled — subtracting 9 when the result
   * exceeds 9, which is equivalent to summing the doubled value's two decimal digits.
   * {@code doubleRightmost} selects whether the doubling starts on the rightmost digit (check-digit
   * computation) or the next one in (validation of a string that already carries its check digit).
   */
  private static int weightedSum(String digits, boolean doubleRightmost) {
    int sum = 0;
    boolean doubling = doubleRightmost;
    for (int i = digits.length() - 1; i >= 0; i--) {
      int d = Character.digit(digits.charAt(i), 10);
      if (doubling) {
        d *= 2;
        if (d > 9) {
          d -= 9;
        }
      }
      sum += d;
      doubling = !doubling;
    }
    return sum;
  }
}
