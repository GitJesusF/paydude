package com.jesusf.paydude.security;

import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.support.SecurityPropertiesFixture;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link JwtService}.
 *
 * <p>Two contracts are pinned: the round-trip of every custom claim through
 * {@code generateToken → parseClaims → extractXxx}, and the rejection paths for invalid
 * tokens (tampered signature, malformed structure, expired). Tests are grouped into
 * {@code @Nested} classes that mirror those contracts:
 *
 * <ul>
 *   <li>{@code TokenRoundTrip} — every claim survives serialization intact, optional claims
 *       deserialize to {@code null} when absent.</li>
 *   <li>{@code TokenRejection} — tampered, malformed, empty, and expired tokens raise the
 *       correct {@code jjwt} exception so {@link JwtAuthenticationFilter} can translate them.</li>
 *   <li>{@code ConfigurationValidation} — malformed or weak signing keys fail during service
 *       construction, not on the first login attempt.</li>
 *   <li>{@code Metadata} — auxiliary getters consumed by other services
 *       (e.g. {@code expiresIn} for the OAuth response).</li>
 *   <li>{@code TokenTyping} — access ({@code at+jwt}) and MFA challenge ({@code mfa+jwt}) tokens
 *       share the signing key, so each parse path must reject the other type (RFC 8725 §3.11).
 *       Without that separation an intercepted challenge would pass as a Bearer token (half a
 *       password escalated to a full session), and an access token would stand in for a verified
 *       password at {@code /mfa/verify}.</li>
 * </ul>
 *
 * <p>Because the service depends only on the {@code jjwt} library and typed
 * {@code SecurityProperties}, the tests skip Spring entirely and construct the configuration
 * through {@link SecurityPropertiesFixture}.
 */
class JwtServiceTest {

  private JwtService jwtService;

  // Token TTL under test: 1 hour in ms. Tests that need a different TTL build their own
  // properties via SecurityPropertiesFixture.withJwtExpiration(...).
  private static final long EXPIRATION_TIME = 1000 * 60 * 60;

  @BeforeEach
  void setUp() {
    jwtService = new JwtService(SecurityPropertiesFixture.withJwtExpiration(EXPIRATION_TIME));
  }

  @Nested
  @DisplayName("Token round-trip — every claim survives generateToken → parseClaims intact")
  class TokenRoundTrip {

    @Test
    @DisplayName("Should generate a valid token whose subject is the user id, not the email")
    void shouldGenerateAndExtractToken() {
      SecurityUser user = createMockUser();

      String token = jwtService.generateToken(Collections.emptyMap(), user);
      Claims claims = jwtService.parseClaims(token);

      assertNotNull(token);
      assertEquals(user.id().toString(), jwtService.extractSubject(claims));
      assertEquals(user.id(), jwtService.extractUserId(claims));
      assertNotEquals(user.getUsername(), jwtService.extractSubject(claims),
          "JWT subject must not contain email PII");
    }

    @Test
    @DisplayName("Should extract custom claims correctly while deriving userId from the authenticated principal")
    void shouldExtractCustomClaims() {
      // The caller's map carries a conflicting userId; the principal must win, otherwise the
      // token could be internally inconsistent (sub=1, userId=12345).
      SecurityUser user = createMockUser();
      Map<String, Object> extraClaims = Map.of(
          JwtClaimNames.USER_ID, 12345L,
          JwtClaimNames.ROLE, "ADMIN"
      );

      String token = jwtService.generateToken(extraClaims, user);
      Claims claims = jwtService.parseClaims(token);

      assertEquals(user.id(), jwtService.extractUserId(claims));
      assertEquals("ADMIN", jwtService.extractRole(claims));
    }

    @Test
    @DisplayName("Should round-trip the user status as a string claim — extractUserStatus returns the matching enum")
    void shouldRoundTripUserStatus() {
      SecurityUser user = createMockUser();
      Map<String, Object> extraClaims = Map.of(JwtClaimNames.STATUS, UserStatus.ACTIVE.name());

      String token = jwtService.generateToken(extraClaims, user);
      Claims claims = jwtService.parseClaims(token);

      assertEquals(UserStatus.ACTIVE, jwtService.extractUserStatus(claims));
    }

    @Test
    @DisplayName("Should round-trip accountExpiresAt as epoch millis with millisecond precision — JWT NumericDate "
        + "claims are integer seconds by spec, but we serialize ours as ms to keep parity with the entity")
    void shouldRoundTripAccountExpiresAt() {
      SecurityUser user = createMockUser();
      // truncatedTo(MILLIS): toEpochMilli() drops sub-ms precision, so an untruncated instant
      // would not compare equal after the round-trip.
      Instant expiresAt = Instant.now().plus(30, ChronoUnit.DAYS).truncatedTo(ChronoUnit.MILLIS);
      Map<String, Object> extraClaims = Map.of(JwtClaimNames.ACCOUNT_EXPIRES_AT, expiresAt.toEpochMilli());

      String token = jwtService.generateToken(extraClaims, user);
      Claims claims = jwtService.parseClaims(token);

      assertEquals(expiresAt, jwtService.extractAccountExpiresAt(claims));
    }

    @Test
    @DisplayName("Should round-trip credentialsExpireAt as epoch millis")
    void shouldRoundTripCredentialsExpireAt() {
      SecurityUser user = createMockUser();
      Instant expiresAt = Instant.now().plus(90, ChronoUnit.DAYS).truncatedTo(ChronoUnit.MILLIS);
      Map<String, Object> extraClaims = Map.of(JwtClaimNames.CREDENTIALS_EXPIRE_AT, expiresAt.toEpochMilli());

      String token = jwtService.generateToken(extraClaims, user);
      Claims claims = jwtService.parseClaims(token);

      assertEquals(expiresAt, jwtService.extractCredentialsExpireAt(claims));
    }

    @Test
    @DisplayName("Should return null for absent optional claims rather than throwing — lets the filter "
        + "distinguish 'never expires' from 'token forged without that claim'")
    void shouldReturnNullForAbsentOptionalClaims() {
      // Mandatory claims (subject/userId/status) have a separate guard in the filter; optional
      // ones must come back as null so absence keeps its domain meaning.
      SecurityUser user = createMockUser();

      String token = jwtService.generateToken(Collections.emptyMap(), user);
      Claims claims = jwtService.parseClaims(token);

      assertEquals(user.id(), jwtService.extractUserId(claims));
      assertNull(jwtService.extractRole(claims));
      assertNull(jwtService.extractUserStatus(claims));
      assertNull(jwtService.extractAccountExpiresAt(claims));
      assertNull(jwtService.extractCredentialsExpireAt(claims));
    }
  }

  @Nested
  @DisplayName("Token rejection — invalid tokens raise the correct jjwt exception")
  class TokenRejection {

    @Test
    @DisplayName("Should fail validation when token signature is tampered")
    void shouldFailWhenTokenIsTampered() {
      SecurityUser user = createMockUser();
      String validToken = jwtService.generateToken(Collections.emptyMap(), user);

      // Keep header and signature, swap the payload: the original HMAC no longer matches, so
      // verification must fail. An implementation that only checked structure would accept this.
      String[] parts = validToken.split("\\.");
      String header = parts[0];
      String signature = parts[2];

      String hackedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
          "{\"sub\":\"999\",\"userId\":999,\"status\":\"ACTIVE\"}".getBytes(StandardCharsets.UTF_8)
      );

      String tamperedToken = header + "." + hackedPayload + "." + signature;

      assertThrows(SignatureException.class, () -> jwtService.parseClaims(tamperedToken));
    }

    @Test
    @DisplayName("Should throw exception for malformed tokens")
    void shouldThrowExceptionForMalformedToken() {
      assertThrows(io.jsonwebtoken.MalformedJwtException.class, () -> jwtService.parseClaims("this.is.not.a.token"));
    }

    @Test
    @DisplayName("Should throw exception for empty tokens")
    void shouldThrowExceptionForEmptyToken() {
      assertThrows(IllegalArgumentException.class, () -> jwtService.parseClaims(""));
    }

    @Test
    @DisplayName("Should throw ExpiredJwtException when token is expired")
    void shouldThrowExceptionWhenTokenIsExpired() {
      // A negative TTL makes generateToken produce an exp in the past — no clock mocking needed.
      JwtService expiredService = new JwtService(SecurityPropertiesFixture.withJwtExpiration(-1000L));
      SecurityUser user = createMockUser();

      String token = expiredService.generateToken(Collections.emptyMap(), user);

      assertThrows(io.jsonwebtoken.ExpiredJwtException.class, () -> expiredService.parseClaims(token));
    }
  }

  @Nested
  @DisplayName("Configuration validation — invalid signing keys fail fast")
  class ConfigurationValidation {

    @Test
    @DisplayName("Should reject malformed Base64 secrets at service construction")
    void shouldRejectMalformedBase64SecretAtConstruction() {
      IllegalStateException ex = assertThrows(IllegalStateException.class,
          () -> new JwtService(SecurityPropertiesFixture.withJwtSecretKey("not-base64%%%")));

      assertTrue(ex.getMessage().contains("application.security.jwt.secret-key"));
    }

    @Test
    @DisplayName("Should reject Base64 secrets that decode below the HS256 256-bit minimum")
    void shouldRejectWeakSecretAtConstruction() {
      String weakButBase64 = Base64.getEncoder()
          .encodeToString("too-short".getBytes(StandardCharsets.UTF_8));

      IllegalStateException ex = assertThrows(IllegalStateException.class,
          () -> new JwtService(SecurityPropertiesFixture.withJwtSecretKey(weakButBase64)));

      assertTrue(ex.getMessage().contains("256 bits"));
    }
  }

  @Nested
  @DisplayName("Metadata — auxiliary getters consumed by other services")
  class Metadata {

    @Test
    @DisplayName("getExpirationSeconds() returns the configured millisecond expiration divided by 1000 — "
        + "exposed for AuthService to populate the OAuth-style 'expires_in' field without re-parsing the token")
    void shouldExposeExpirationInSeconds() {
      // RFC 6749 §5.1 defines expires_in in seconds; the conversion lives here, not in callers.
      assertEquals(EXPIRATION_TIME / 1000L, jwtService.getExpirationSeconds());
    }
  }

  @Nested
  @DisplayName("Token typing — at+jwt and mfa+jwt never substitute for each other")
  class TokenTyping {

    @Test
    @DisplayName("a challenge token round-trips through parseMfaChallengeClaims with sub = userId")
    void shouldRoundTripChallengeToken() {
      String challenge = jwtService.generateMfaChallengeToken(42L);

      Claims claims = jwtService.parseMfaChallengeClaims(challenge);

      assertEquals("42", claims.getSubject());
      assertEquals(42L, jwtService.extractUserId(claims));
      // Deliberately minimal: no status/role/email — the challenge authorizes one code attempt,
      // and verifyMfa re-reads account state from the DB rather than trusting a snapshot.
      assertNull(claims.get(JwtClaimNames.STATUS, String.class));
      assertNull(claims.get(JwtClaimNames.ROLE, String.class));
    }

    @Test
    @DisplayName("the challenge lifetime comes from mfa.challenge-expiration, not the access TTL")
    void shouldUseChallengeExpiration() {
      // The fixture pins challenge-expiration=5m against this setUp's 1h access TTL: inheriting
      // the access TTL would widen the redemption window 12x.
      Claims claims = jwtService.parseMfaChallengeClaims(jwtService.generateMfaChallengeToken(42L));

      long lifetimeSeconds = (claims.getExpiration().getTime() - claims.getIssuedAt().getTime()) / 1000L;
      assertEquals(300L, lifetimeSeconds, "challenge must live exactly mfa.challenge-expiration");
      assertEquals(300L, jwtService.getMfaChallengeExpirationSeconds());
    }

    @Test
    @DisplayName("parseClaims (the Bearer path) rejects a challenge token before reading any claim")
    void shouldRejectChallengeTokenAsBearer() {
      String challenge = jwtService.generateMfaChallengeToken(42L);

      // The signature is valid; typ=mfa+jwt alone must reject it. (The filter's mandatory-claims
      // guard would also catch it — explicit beats accidental.)
      assertThrows(JwtException.class, () -> jwtService.parseClaims(challenge),
          "a signed MFA challenge must never authenticate an API request");
    }

    @Test
    @DisplayName("parseMfaChallengeClaims rejects an access token — a session is not a password proof")
    void shouldRejectAccessTokenAsChallenge() {
      String accessToken = jwtService.generateToken(new HashMap<>(), createMockUser());

      assertThrows(JwtException.class, () -> jwtService.parseMfaChallengeClaims(accessToken),
          "an access token must never stand in for the password stage at /mfa/verify");
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Builders
  // ---------------------------------------------------------------------------------------------

  // Values are arbitrary; the email exists only to prove it never leaks into the token.
  private SecurityUser createMockUser() {
    return new SecurityUser(
        1L,
        "example@test.com",
        "password",
        UserStatus.ACTIVE,
        null,   // no account expiry
        null,   // no credentials expiry
        false,  // mfaEnabled — not carried in the token
        List.of(new SimpleGrantedAuthority("ROLE_USER"))
    );
  }
}
