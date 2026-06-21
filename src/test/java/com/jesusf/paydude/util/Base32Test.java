package com.jesusf.paydude.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for {@link Base32}, pinned against the official RFC 4648 §10 test vectors.
 *
 * <p>A hand-written codec earns its keep only if it is bit-exact against the spec: the encoded
 * secret travels into an authenticator app we do not control, so any deviation produces TOTP
 * codes that never match — an enrollment that bricks the account at the next login. The §10
 * vectors are the contract both sides implement.
 */
class Base32Test {

  // Official RFC 4648 §10 vectors. The RFC publishes them WITH padding ("MY======"); our encode
  // emits the unpadded variant authenticators expect (Google Authenticator rejects '='), so the
  // expected column is the vector stripped of '='. decode accepts both forms.

  @ParameterizedTest(name = "encode(\"{0}\") == \"{1}\"")
  @CsvSource({
      "f,      MY",
      "fo,     MZXQ",
      "foo,    MZXW6",
      "foob,   MZXW6YQ",
      "fooba,  MZXW6YTB",
      "foobar, MZXW6YTBOI"
  })
  @DisplayName("encode matches the RFC 4648 §10 vectors (unpadded form)")
  void shouldEncodePerRfc4648(String ascii, String expected) {
    assertEquals(expected, Base32.encode(ascii.getBytes(StandardCharsets.US_ASCII)));
  }

  @ParameterizedTest(name = "decode(\"{1}\") == \"{0}\"")
  @CsvSource({
      "f,      MY",
      "fo,     MZXQ",
      "foo,    MZXW6",
      "foob,   MZXW6YQ",
      "fooba,  MZXW6YTB",
      "foobar, MZXW6YTBOI"
  })
  @DisplayName("decode matches the RFC 4648 §10 vectors")
  void shouldDecodePerRfc4648(String expectedAscii, String encoded) {
    assertArrayEquals(expectedAscii.getBytes(StandardCharsets.US_ASCII), Base32.decode(encoded));
  }

  @Test
  @DisplayName("empty input round-trips to empty output")
  void shouldHandleEmptyInput() {
    assertEquals("", Base32.encode(new byte[0]));
    assertArrayEquals(new byte[0], Base32.decode(""));
  }

  @Test
  @DisplayName("decode is liberal: lower-case and trailing padding are accepted")
  void shouldDecodeLowerCaseAndPadded() {
    // Postel: the secret may come back hand-typed from an authenticator UI that shows it in
    // lower case, or from a tool that emits the RFC's canonical padding.
    byte[] expected = "foobar".getBytes(StandardCharsets.US_ASCII);
    assertArrayEquals(expected, Base32.decode("mzxw6ytboi"));
    assertArrayEquals(expected, Base32.decode("MZXW6YTBOI======"));
  }

  @Test
  @DisplayName("decode rejects characters outside the RFC 4648 alphabet")
  void shouldRejectInvalidCharacters() {
    // '0', '1', '8' and '9' are deliberately excluded from the Base32 alphabet (visual ambiguity
    // with O/I/B/g). Accepting them silently would yield a secret different from the provisioned one.
    assertThrows(IllegalArgumentException.class, () -> Base32.decode("MZXW0"));
    assertThrows(IllegalArgumentException.class, () -> Base32.decode("MZ XW"));
  }

  @Test
  @DisplayName("random 20-byte secrets round-trip losslessly (the TOTP secret length)")
  void shouldRoundTripRandomSecrets() {
    // The real use case: 20 SecureRandom bytes (160 bits, RFC 4226 §4). 100 iterations cover
    // the five possible final-quantum offsets with margin.
    SecureRandom random = new SecureRandom();
    for (int i = 0; i < 100; i++) {
      byte[] secret = new byte[20];
      random.nextBytes(secret);
      assertArrayEquals(secret, Base32.decode(Base32.encode(secret)),
          "round-trip must be lossless for any byte content");
    }
  }
}
