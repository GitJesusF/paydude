package com.jesusf.paydude.security;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.enums.UserStatus;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Issues, parses and validates the application's JWTs.
 *
 * <p>The single entry point for parsing is {@link #parseClaims(String)}, which both verifies the
 * HMAC signature and rejects expired tokens (jjwt's {@code parseSignedClaims} throws
 * {@code ExpiredJwtException} before returning). Callers obtain a {@link Claims} object once and
 * then use the {@code extract*} helpers to read individual claims, avoiding redundant re-parsing
 * of the same token on the hot path of {@code JwtAuthenticationFilter}.
 *
 * <p><b>Explicit typing (RFC 8725 §3.11 / RFC 9068).</b> The service mints two token kinds and
 * brands each with a JOSE {@code typ} header: access tokens carry {@code at+jwt} (the RFC 9068
 * media type), MFA challenge tokens carry {@code mfa+jwt}. Each parse entry point requires its
 * own type, so the two can never be confused even though they share the signing key: a stolen
 * challenge token presented as a Bearer credential dies in {@link #parseClaims(String)} before
 * any claim is read, and an access token posted to {@code /v1/auth/mfa/verify} dies the same way
 * in {@link #parseMfaChallengeClaims(String)}. This is the header-level defence; the differing
 * claim sets (a challenge token has no {@code status}/{@code role}) are the redundant second.
 *
 * <p>Configuration is injected via {@link SecurityProperties.Jwt}; the previous {@code @Value}
 * fields have been removed so a missing or malformed secret/expiration fails at boot rather than
 * on the first login attempt.
 */
@Service
public class JwtService {

  /** JOSE {@code typ} of an access token — RFC 9068's registered media type. */
  static final String ACCESS_TOKEN_TYPE = "at+jwt";

  /** JOSE {@code typ} of the short-lived MFA challenge token minted between password and TOTP. */
  static final String MFA_CHALLENGE_TOKEN_TYPE = "mfa+jwt";

  private final SecurityProperties.Jwt jwtProperties;
  private final SecurityProperties.Mfa mfaProperties;
  private final SecretKey signingKey;

  public JwtService(SecurityProperties securityProperties) {
    this.jwtProperties = securityProperties.jwt();
    this.mfaProperties = securityProperties.mfa();
    this.signingKey = createSigningKey(jwtProperties.secretKey());
  }

  /**
   * Builds and HMAC-signs an access token for the given principal.
   *
   * @param extraClaims authorization claims to embed; their names come from {@link JwtClaimNames}
   * @param principal the authenticated principal — its numeric id becomes the token subject
   * @return the compact, signed JWT string
   */
  public String generateToken(Map<String, Object> extraClaims, SecurityUser principal) {
    Objects.requireNonNull(extraClaims, "extraClaims must not be null");
    Objects.requireNonNull(principal, "principal must not be null");
    Long userId = Objects.requireNonNull(principal.id(), "principal id must not be null");

    Map<String, Object> claims = new HashMap<>(extraClaims);
    claims.put(JwtClaimNames.USER_ID, userId);

    Instant now = Instant.now();
    return Jwts.builder()
        .header().type(ACCESS_TOKEN_TYPE).and()
        .claims(claims)
        .subject(userId.toString())
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusMillis(jwtProperties.expiration())))
        .signWith(signingKey)
        .compact();
  }

  /**
   * Mints the one-shot MFA challenge token returned by {@code POST /v1/auth/login} when the
   * account has TOTP enabled: proof that the password stage passed, redeemable only at
   * {@code POST /v1/auth/mfa/verify} within {@code application.security.mfa.challenge-expiration}.
   *
   * <p>Deliberately minimal: {@code typ = mfa+jwt} plus the subject/user id. No {@code status},
   * {@code role} or expiry claims — the token authorizes nothing but a code attempt, and the
   * account state is re-checked from the database at verification time (unlike an access token,
   * this flow is not latency-critical, so there is no reason to trust a snapshot).
   *
   * @param userId the user who just passed the password check
   * @return the compact, signed challenge token
   */
  public String generateMfaChallengeToken(Long userId) {
    Objects.requireNonNull(userId, "userId must not be null");
    Instant now = Instant.now();
    return Jwts.builder()
        .header().type(MFA_CHALLENGE_TOKEN_TYPE).and()
        .claim(JwtClaimNames.USER_ID, userId)
        .subject(userId.toString())
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plus(mfaProperties.challengeExpiration())))
        .signWith(signingKey)
        .compact();
  }

  /**
   * Parses, signature-verifies and expiration-checks an <b>access</b> token in a single call,
   * additionally requiring the {@code typ: at+jwt} header — an MFA challenge token (or any other
   * future token kind) presented as a Bearer credential is rejected here, before any claim is
   * trusted.
   *
   * <p>Throws {@code io.jsonwebtoken.JwtException} (or {@link IllegalArgumentException} for empty
   * input) on any failure — callers should let those propagate to the security exception channel
   * rather than swallow them.
   */
  public Claims parseClaims(String token) {
    return parseTyped(token, ACCESS_TOKEN_TYPE);
  }

  /**
   * Parses, signature-verifies and expiration-checks an MFA <b>challenge</b> token, requiring the
   * {@code typ: mfa+jwt} header — the mirror image of {@link #parseClaims(String)}, so an access
   * token can never stand in for a passed password check at {@code /v1/auth/mfa/verify}.
   */
  public Claims parseMfaChallengeClaims(String token) {
    return parseTyped(token, MFA_CHALLENGE_TOKEN_TYPE);
  }

  private Claims parseTyped(String token, String requiredType) {
    Jws<Claims> jws = Jwts.parser()
        .verifyWith(signingKey)
        .build()
        .parseSignedClaims(token);
    // jjwt's require(...) covers payload claims only, so the typ header is asserted by hand. The
    // signature was already verified above — a tampered typ cannot survive to this comparison.
    if (!requiredType.equals(jws.getHeader().getType())) {
      throw new JwtException("Unexpected token type: required " + requiredType);
    }
    return jws.getPayload();
  }

  /**
   * Token lifetime in seconds, derived from {@code application.security.jwt.expiration}.
   * Exposed so {@code AuthServiceImpl} can populate the OAuth-style {@code expires_in} field
   * without parsing the token it just emitted.
   */
  public long getExpirationSeconds() {
    return jwtProperties.expiration() / 1000L;
  }

  /**
   * MFA challenge-token lifetime in seconds, derived from
   * {@code application.security.mfa.challenge-expiration}. Exposed so the login response can tell
   * the client how long it has to submit the TOTP code, mirroring {@code expires_in}.
   */
  public long getMfaChallengeExpirationSeconds() {
    return mfaProperties.challengeExpiration().getSeconds();
  }

  public String extractSubject(Claims claims) {
    return claims.getSubject();
  }

  public Long extractUserId(Claims claims) {
    Number userId = claims.get(JwtClaimNames.USER_ID, Number.class);
    return userId != null ? userId.longValue() : null;
  }

  public String extractRole(Claims claims) {
    return claims.get(JwtClaimNames.ROLE, String.class);
  }

  public UserStatus extractUserStatus(Claims claims) {
    String status = claims.get(JwtClaimNames.STATUS, String.class);
    return status != null ? UserStatus.valueOf(status) : null;
  }

  public Instant extractAccountExpiresAt(Claims claims) {
    return extractEpochMillisClaim(claims, JwtClaimNames.ACCOUNT_EXPIRES_AT);
  }

  public Instant extractCredentialsExpireAt(Claims claims) {
    return extractEpochMillisClaim(claims, JwtClaimNames.CREDENTIALS_EXPIRE_AT);
  }

  private Instant extractEpochMillisClaim(Claims claims, String claimName) {
    Number value = claims.get(claimName, Number.class);
    return value != null ? Instant.ofEpochMilli(value.longValue()) : null;
  }

  private static SecretKey createSigningKey(String base64Secret) {
    try {
      byte[] keyBytes = Decoders.BASE64.decode(base64Secret);
      return Keys.hmacShaKeyFor(keyBytes);
    } catch (RuntimeException e) {
      throw new IllegalStateException(
          "Invalid application.security.jwt.secret-key: must be Base64-encoded and decode to "
              + "at least 256 bits for HS256",
          e
      );
    }
  }
}
