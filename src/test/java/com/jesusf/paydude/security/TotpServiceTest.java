package com.jesusf.paydude.security;

import com.jesusf.paydude.util.Base32;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.util.OptionalLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link TotpService}, pinned against the official RFC 6238 Appendix B test
 * vectors (which exercise the full RFC 4226 HOTP truncation underneath).
 *
 * <p>This is the justification for implementing TOTP by hand instead of importing a library: the
 * RFC ships an authoritative answer key. If these vectors pass, the implementation interoperates
 * with every authenticator app — there is no behavioural surface beyond them (plus the window
 * policy, tested separately against the real clock).
 */
class TotpServiceTest {

  // Official vector material: the ASCII secret "12345678901234567890" (20 bytes — the length
  // RFC 4226 §4 recommends for SHA-1). The published codes are 8 digits; production uses 6, but
  // the algorithm is identical modulo 10^digits, so both lengths are pinned.
  private static final byte[] RFC_SECRET =
      "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
  private static final String RFC_SECRET_BASE32 = Base32.encode(RFC_SECRET);

  private final TotpService totpService = new TotpService();

  @Nested
  @DisplayName("RFC 6238 Appendix B vectors (HMAC-SHA1)")
  class RfcVectors {

    @ParameterizedTest(name = "T={0}s -> {1}")
    @CsvSource({
        // unixTime,    expected 8-digit code (SHA1 column of the Appendix B table)
        "59,            94287082",
        "1111111109,    07081804",
        "1111111111,    14050471",
        "1234567890,    89005924",
        "2000000000,    69279037",
        "20000000000,   65353130"
    })
    @DisplayName("8-digit codes match the published table")
    void shouldMatchEightDigitVectors(long unixTime, String expected) {
      long step = unixTime / TotpService.TIME_STEP_SECONDS;
      assertEquals(expected, TotpService.hotp(RFC_SECRET, step, 8));
    }

    @ParameterizedTest(name = "T={0}s -> {1}")
    @CsvSource({
        // Same vectors truncated to 6 digits: HOTP is binCode mod 10^digits, so the 6-digit
        // code is exactly the last 6 digits of the 8-digit one.
        "59,            287082",
        "1111111109,    081804",
        "1111111111,    050471",
        "1234567890,    005924",
        "2000000000,    279037",
        "20000000000,   353130"
    })
    @DisplayName("6-digit codes (the production length) derive from the same vectors")
    void shouldMatchSixDigitVectors(long unixTime, String expected) {
      long step = unixTime / TotpService.TIME_STEP_SECONDS;
      assertEquals(expected, totpService.codeAt(RFC_SECRET_BASE32, step));
    }
  }

  @Nested
  @DisplayName("findMatchingStep — ±1-step window over the real clock")
  class WindowMatching {

    @Test
    @DisplayName("accepts the current step and both ±1 neighbours, reporting the matched step")
    void shouldAcceptCodesInsideTheWindow() {
      // The returned step is the ABSOLUTE step of the presented code — stable even if the test
      // crosses a step boundary between generating and verifying (still within ±1).
      long step = totpService.currentTimeStep();
      for (long candidate = step - 1; candidate <= step + 1; candidate++) {
        String code = totpService.codeAt(RFC_SECRET_BASE32, candidate);
        OptionalLong matched = totpService.findMatchingStep(RFC_SECRET_BASE32, code);
        assertTrue(matched.isPresent(), "code for step " + candidate + " must verify");
        assertEquals(candidate, matched.getAsLong(),
            "the matched step must identify the code's own step (the replay-guard key)");
      }
    }

    @Test
    @DisplayName("rejects a code two steps stale — beyond the RFC 6238 §5.2 skew allowance")
    void shouldRejectCodesOutsideTheWindow() {
      String staleCode = totpService.codeAt(RFC_SECRET_BASE32, totpService.currentTimeStep() - 2);
      // A 10^-6 collision with a window code is theoretically possible; the fixed secret and
      // deterministic steps keep this stable in practice.
      assertTrue(totpService.findMatchingStep(RFC_SECRET_BASE32, staleCode).isEmpty(),
          "a code older than the ±1 window must not verify");
    }

    @ParameterizedTest(name = "\"{0}\" is rejected before any HMAC")
    // The Arabic-Indic case ("١٢٣٤٥٦") pins the shape check as strict ASCII '0'-'9':
    // Character.isDigit would accept those digits, but hotp() only emits ASCII, so they
    // could never match.
    @CsvSource(value = {"12345", "1234567", "12a456", "١٢٣٤٥٦", "''", "null"}, nullValues = "null")
    @DisplayName("malformed input shapes never reach the cryptographic comparison")
    void shouldRejectMalformedCodes(String code) {
      assertTrue(totpService.findMatchingStep(RFC_SECRET_BASE32, code).isEmpty());
    }
  }

  @Nested
  @DisplayName("Secret generation and provisioning URI")
  class Provisioning {

    @Test
    @DisplayName("generates 160-bit secrets (32 Base32 chars) that are not repeated")
    void shouldGenerateFreshSecrets() {
      String first = totpService.generateSecret();
      String second = totpService.generateSecret();
      // 20 bytes × 8 / 5 bits per char = exactly 32 chars, no padding.
      assertEquals(32, first.length());
      assertTrue(first.matches("[A-Z2-7]+"), "secret must be canonical upper-case Base32");
      assertNotEquals(first, second, "two generations must not collide (SecureRandom)");
    }

    @Test
    @DisplayName("builds the otpauth:// Key-Uri with the parameters authenticators expect")
    void shouldBuildProvisioningUri() {
      String uri = totpService.provisioningUri("PayDude", "maria@example.com", "JBSWY3DPEHPK3PXP");

      // issuer:account label with '@' percent-encoded, issuer repeated as a query param, and
      // the three algorithm parameters pinned to the authenticator-ecosystem defaults.
      assertEquals("otpauth://totp/PayDude:maria%40example.com"
              + "?secret=JBSWY3DPEHPK3PXP&issuer=PayDude&algorithm=SHA1&digits=6&period=30",
          uri);
      assertFalse(uri.contains("+"), "spaces must be %20-encoded, never '+', inside a URI");
    }
  }
}
