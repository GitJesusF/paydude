package com.jesusf.paydude.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for {@link AccountNumberMasker}. The contract is small but load-bearing: every
 * account number that reaches a log line goes through this, so the last-four reveal and the
 * short-value / null guards must be pinned.
 */
class AccountNumberMaskerTest {

  @Test
  @DisplayName("shows only the last four characters of a full account number")
  void masksAllButLastFour() {
    assertEquals("****0123", AccountNumberMasker.mask("4521234567890123"));
    assertEquals("****5678", AccountNumberMasker.mask("12345678"));
  }

  @Test
  @DisplayName("uses a fixed-width prefix, so the original length is not leaked")
  void fixedWidthPrefix() {
    // A 16-char and an 8-char number with the same suffix mask to the same string: the prefix
    // is always "****", never proportional to the original length.
    assertEquals(AccountNumberMasker.mask("9999999999990123"), AccountNumberMasker.mask("99990123"));
  }

  @Test
  @DisplayName("fully masks values too short to reveal a tail")
  void masksShortValues() {
    assertEquals("****", AccountNumberMasker.mask("1234")); // exactly the visible length → no reveal
    assertEquals("****", AccountNumberMasker.mask("12"));   // shorter still
    assertEquals("****2345", AccountNumberMasker.mask("12345")); // one over → tail revealed
  }

  @Test
  @DisplayName("null and blank mask to the bare marker")
  void masksNullAndBlank() {
    assertEquals("****", AccountNumberMasker.mask(null));
    assertEquals("****", AccountNumberMasker.mask(""));
  }
}
