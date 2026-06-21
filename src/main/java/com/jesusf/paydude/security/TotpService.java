package com.jesusf.paydude.security;

import com.jesusf.paydude.util.Base32;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.OptionalLong;

/**
 * Time-based one-time passwords — TOTP (RFC 6238) over HOTP (RFC 4226).
 *
 * <p>Implemented from the RFCs against the JCA's {@code HmacSHA1} primitive rather than via a
 * third-party OTP library: the whole algorithm is one HMAC plus the §5.3 dynamic truncation, the
 * RFC ships official test vectors that {@code TotpServiceTest} pins (Appendix B of RFC 6238), and
 * not adding a dependency keeps the supply-chain surface the DevSecOps pipeline scans that much
 * smaller. No custom cryptography is involved — the only crypto here is the JDK's HMAC.
 *
 * <p>Parameters are the authenticator-ecosystem defaults every TOTP app assumes when reading an
 * {@code otpauth://} URI: SHA-1, 6 digits, 30-second time step, {@code T0 = 0}. SHA-1's collision
 * weakness is irrelevant in the HMAC construction (RFC 6238 §1.2 keeps it as the interoperable
 * baseline); several mainstream authenticators silently ignore the {@code algorithm} parameter and
 * compute SHA-1 regardless, so advertising SHA-256 would break enrollment for those users.
 *
 * <p>Verification accepts a ±{@value #VERIFICATION_WINDOW_STEPS}-step window (RFC 6238 §5.2 —
 * network delay plus device clock drift) and reports <i>which</i> step matched, so the caller can
 * persist it and reject any code at or before that step ({@code MfaServiceImpl}'s replay guard —
 * §5.2's "the verifier MUST NOT accept the second attempt of the OTP").
 */
@Component
public class TotpService {

  /** Code length. Six digits is the universal authenticator default. */
  public static final int CODE_DIGITS = 6;

  /** Time-step size in seconds ({@code X} in RFC 6238 §4.1). */
  public static final int TIME_STEP_SECONDS = 30;

  /** Steps of clock skew accepted on each side of the current step (RFC 6238 §5.2). */
  public static final int VERIFICATION_WINDOW_STEPS = 1;

  private static final String HMAC_ALGORITHM = "HmacSHA1";

  // RFC 4226 §4 R6: the shared secret SHOULD be the length of the HMAC output — 160 bits for SHA-1.
  private static final int SECRET_LENGTH_BYTES = 20;

  private final SecureRandom secureRandom = new SecureRandom();

  /**
   * Generates a fresh 160-bit shared secret, Base32-encoded for the provisioning URI and for
   * storage. The encoding is the wire format authenticator apps expect; the raw bytes are
   * recovered with {@link Base32#decode} at every verification.
   */
  public String generateSecret() {
    byte[] secret = new byte[SECRET_LENGTH_BYTES];
    secureRandom.nextBytes(secret);
    return Base32.encode(secret);
  }

  /** The current TOTP time step: {@code floor(unixTime / 30)} (RFC 6238 §4.2 with T0 = 0). */
  public long currentTimeStep() {
    return Instant.now().getEpochSecond() / TIME_STEP_SECONDS;
  }

  /**
   * Computes the 6-digit code for a secret at a given time step. Exposed (rather than only a
   * boolean verify) so the enrollment flow and the integration tests can derive the code the
   * authenticator app would display for any step.
   *
   * @param base32Secret the shared secret as stored (Base32)
   * @param timeStep     the TOTP step to compute the code for
   * @return the zero-padded 6-digit code
   */
  public String codeAt(String base32Secret, long timeStep) {
    return hotp(Base32.decode(base32Secret), timeStep, CODE_DIGITS);
  }

  /**
   * Checks a submitted code against the current step and its ±1 neighbours, and reports which
   * step matched so the caller can enforce single-use.
   *
   * <p>Every candidate is compared with {@link MessageDigest#isEqual} (constant-time): a timing
   * oracle over a 6-digit space is exactly the kind of side channel that turns a brute-forceable
   * code into a cheaply-guessable one.
   *
   * @param base32Secret the shared secret as stored (Base32)
   * @param code         the submitted code (exactly 6 ASCII digits to be considered at all)
   * @return the matching time step, or empty when the code matches none of the window
   */
  public OptionalLong findMatchingStep(String base32Secret, String code) {
    // ASCII '0'-'9' explicitly, not Character::isDigit: the latter also accepts Arabic-Indic and
    // other Unicode digit blocks, which can never match the ASCII bytes hotp() emits.
    if (code == null || code.length() != CODE_DIGITS
        || !code.chars().allMatch(c -> c >= '0' && c <= '9')) {
      return OptionalLong.empty();
    }
    byte[] secret = Base32.decode(base32Secret);
    byte[] submitted = code.getBytes(StandardCharsets.US_ASCII);
    long currentStep = currentTimeStep();
    for (long step = currentStep - VERIFICATION_WINDOW_STEPS;
         step <= currentStep + VERIFICATION_WINDOW_STEPS; step++) {
      byte[] expected = hotp(secret, step, CODE_DIGITS).getBytes(StandardCharsets.US_ASCII);
      if (MessageDigest.isEqual(expected, submitted)) {
        return OptionalLong.of(step);
      }
    }
    return OptionalLong.empty();
  }

  /**
   * Builds the {@code otpauth://totp/...} provisioning URI (the de-facto Key Uri Format) that the
   * client renders as a QR code. The label is {@code issuer:account} and the issuer is repeated as
   * a query parameter — both required for the entry to display correctly across authenticator apps.
   *
   * @param issuer  the service name shown in the authenticator (from {@code application.security.mfa.issuer})
   * @param account the user-facing account identifier (their email)
   * @param base32Secret the shared secret in Base32
   * @return the full otpauth URI
   */
  public String provisioningUri(String issuer, String account, String base32Secret) {
    String encodedIssuer = urlEncode(issuer);
    return "otpauth://totp/" + encodedIssuer + ":" + urlEncode(account)
        + "?secret=" + base32Secret
        + "&issuer=" + encodedIssuer
        + "&algorithm=SHA1"
        + "&digits=" + CODE_DIGITS
        + "&period=" + TIME_STEP_SECONDS;
  }

  /**
   * HOTP (RFC 4226 §5.3): HMAC the 8-byte big-endian counter, dynamically truncate to a 31-bit
   * integer (low nibble of the last byte selects the offset; the sign bit is masked), then take
   * the low {@code digits} decimal digits, zero-padded.
   *
   * <p>Package-private so {@code TotpServiceTest} can pin the RFC 6238 Appendix B vectors, which
   * are published as 8-digit codes.
   */
  static String hotp(byte[] secret, long counter, int digits) {
    byte[] counterBytes = ByteBuffer.allocate(Long.BYTES).putLong(counter).array();
    byte[] hash = hmacSha1(secret, counterBytes);

    int offset = hash[hash.length - 1] & 0x0F;
    int binaryCode = ((hash[offset] & 0x7F) << 24)
        | ((hash[offset + 1] & 0xFF) << 16)
        | ((hash[offset + 2] & 0xFF) << 8)
        | (hash[offset + 3] & 0xFF);

    int code = binaryCode % (int) Math.pow(10, digits);
    // Zero-pad by hand instead of String.format("%0" + digits + "d"): Integer.toString always
    // emits ASCII digits (no locale-dependent numerals to drift from authenticator apps), and a
    // format string assembled at runtime is a FORMAT_STRING_MANIPULATION finding for the SAST
    // gate even though an int cannot smuggle format directives into it.
    String decimal = Integer.toString(code);
    return "0".repeat(digits - decimal.length()) + decimal;
  }

  private static byte[] hmacSha1(byte[] key, byte[] message) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
      return mac.doFinal(message);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      // HmacSHA1 is mandated by the JCA spec for every JRE; an empty key is the only realistic
      // trigger and would be a programming error upstream — surface it, never return a weak code.
      throw new IllegalStateException("Unable to compute HMAC-SHA1 for TOTP", e);
    }
  }

  private static String urlEncode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }
}
