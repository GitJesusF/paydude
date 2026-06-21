package com.jesusf.paydude.util;

import java.util.Arrays;

/**
 * Base32 codec (RFC 4648 §6) for the TOTP shared secret.

 * <p>The JDK ships Base64 ({@code java.util.Base64}) but not Base32, and the authenticator-app
 * ecosystem standardised on Base32 for {@code otpauth://} provisioning URIs: its alphabet
 * ({@code A–Z2–7}) is case-insensitive, has no visually ambiguous characters ({@code 0/O},
 * {@code 1/l/I}) and no URL-hostile symbols — properties that matter for a value users may have
 * to type by hand when a QR scan is not possible. Implemented here from the RFC (and pinned by
 * its §10 test vectors in {@code Base32Test}) rather than pulling Apache Commons Codec in as a
 * dependency for two 40-line methods.
 *
 * <p>{@link #encode(byte[])} emits the canonical upper-case alphabet <b>without padding</b> — the
 * convention of every mainstream authenticator (Google Authenticator rejects {@code =} outright).
 * {@link #decode(String)} is liberal in what it accepts (RFC 9413 robustness): lower-case input
 * and trailing {@code =} padding are tolerated, anything else throws.
 */
public final class Base32 {

  private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

  // Reverse lookup: ASCII code point -> 5-bit value, -1 for characters outside the alphabet.
  private static final int[] REVERSE = new int[128];

  static {
    Arrays.fill(REVERSE, -1);
    for (int i = 0; i < ALPHABET.length; i++) {
      REVERSE[ALPHABET[i]] = i;
      REVERSE[Character.toLowerCase(ALPHABET[i])] = i;
    }
  }

  private Base32() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }

  /**
   * Encodes bytes to unpadded upper-case Base32: a rolling bit buffer that emits one alphabet
   * character per 5 accumulated bits, plus the RFC's final-quantum rule (left-align whatever bits
   * remain into one last character instead of padding with {@code =}).
   *
   * @param data the raw bytes (e.g. the 20-byte TOTP secret)
   * @return the Base32 string, empty for empty input
   */
  public static String encode(byte[] data) {
    StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);
    int buffer = 0;
    int bitsInBuffer = 0;
    for (byte b : data) {
      buffer = (buffer << 8) | (b & 0xFF);
      bitsInBuffer += 8;
      while (bitsInBuffer >= 5) {
        bitsInBuffer -= 5;
        out.append(ALPHABET[(buffer >>> bitsInBuffer) & 0x1F]);
      }
    }
    if (bitsInBuffer > 0) {
      out.append(ALPHABET[(buffer << (5 - bitsInBuffer)) & 0x1F]);
    }
    return out.toString();
  }

  /**
   * Decodes a Base32 string back to bytes. Case-insensitive; trailing {@code =} padding is
   * accepted and ignored. Leftover bits that do not complete a byte (the final partial quantum)
   * are discarded, per the RFC's decoding rule.
   *
   * @param base32 the encoded string
   * @return the decoded bytes
   * @throws IllegalArgumentException if the input contains a character outside the alphabet
   */
  public static byte[] decode(String base32) {
    String trimmed = stripTrailingPadding(base32);
    byte[] out = new byte[trimmed.length() * 5 / 8];
    int buffer = 0;
    int bitsInBuffer = 0;
    int index = 0;
    for (int i = 0; i < trimmed.length(); i++) {
      char c = trimmed.charAt(i);
      int value = c < REVERSE.length ? REVERSE[c] : -1;
      if (value < 0) {
        throw new IllegalArgumentException("Invalid Base32 character at position " + i);
      }
      buffer = (buffer << 5) | value;
      bitsInBuffer += 5;
      if (bitsInBuffer >= 8) {
        bitsInBuffer -= 8;
        out[index++] = (byte) ((buffer >>> bitsInBuffer) & 0xFF);
      }
    }
    return out;
  }

  private static String stripTrailingPadding(String input) {
    int end = input.length();
    while (end > 0 && input.charAt(end - 1) == '=') {
      end--;
    }
    return input.substring(0, end);
  }
}
