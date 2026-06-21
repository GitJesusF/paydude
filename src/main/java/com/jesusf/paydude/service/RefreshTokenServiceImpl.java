package com.jesusf.paydude.service;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.entity.RefreshToken;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.repository.RefreshTokenRepository;
import com.jesusf.paydude.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Implementation of the refresh-token lifecycle.
 *
 * <p>Issuance generates 32 bytes (256 bits) of cryptographic entropy via a shared
 * {@link SecureRandom}, encodes the bytes with URL-safe Base64 (no padding) for transport
 * compactness, and persists the SHA-256 hex digest only. The raw bytes never see disk; the
 * unhashed string exists in JVM memory only for the duration of the request that returns it
 * to the client.
 *
 * <p>Rotation acquires a pessimistic row lock on the presented token's row before mutating it,
 * preventing the race where two concurrent {@code /refresh} calls with the same raw token both
 * succeed (which would fork the chain). The second caller waits, finds the row already revoked,
 * and trips reuse detection.
 */
@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
class RefreshTokenServiceImpl implements RefreshTokenService {

  /**
   * 32 bytes = 256 bits of entropy. Brute-forcing the token space at any feasible request rate
   * is statistically impossible — at one trillion guesses per second per IP it would take
   * roughly 5×10⁵⁶ years to enumerate. The rate-limit filter caps the practical rate well below
   * that anyway.
   */
  private static final int RAW_TOKEN_BYTES = 32;

  // Thread-safe and seeded once. Reusing one instance avoids the cost of re-seeding from
  // /dev/urandom on every call.
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

  private final RefreshTokenRepository refreshTokenRepository;
  private final UserRepository userRepository;
  private final SecurityProperties securityProperties;
  private final RefreshTokenFamilyRevocationService familyRevocationService;
  // Records TOKEN_REUSE_DETECTED (a stolen-token replay) and LOGOUT to the security audit log.
  // record(...) is REQUIRES_NEW + fail-safe — the reuse event survives rotate()'s rollback, exactly
  // like the family revocation above.
  private final SecurityAuditService securityAuditService;

  @Override
  @Transactional(rollbackFor = Exception.class)
  public IssuedRefreshToken issueNewFamily(Long userId, String clientIp, String userAgent) {
    Issued issued = issue(userId, UUID.randomUUID(), clientIp, userAgent);
    return new IssuedRefreshToken(issued.rawToken(), issued.entity().getExpiresAt());
  }

  @Override
  @Transactional(rollbackFor = Exception.class, isolation = Isolation.READ_COMMITTED)
  public RotatedTokens rotate(String rawRefreshToken, String clientIp, String userAgent) {
    final String hash = sha256Hex(rawRefreshToken);
    final Instant now = Instant.now();

    // PESSIMISTIC_WRITE — serialises concurrent rotations of the same row. See repo for context.
    final RefreshToken presented = refreshTokenRepository.findByTokenHashForUpdate(hash)
        .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));

    if (presented.getRevokedAt() != null) {
      // REUSE DETECTION. The token was already used (rotated, logged out, or admin-revoked).
      // Whoever just presented it is either the legitimate client retrying after a network blip
      // OR an attacker replaying a stolen token. We cannot distinguish, so we assume the worst:
      // revoke the entire family. The legitimate client will be forced to re-login — annoying,
      // but the right tradeoff for a financial app.
      int killed = familyRevocationService.revokeFamilyForReuseDetection(
          presented.getUserId(), presented.getFamilyId(), now
      );
      log.warn(
          "Refresh token reuse detected — revoking family {} for user {} ({} active tokens killed)",
          presented.getFamilyId(), presented.getUserId(), killed
      );
      securityAuditService.record(SecurityAuditEventType.TOKEN_REUSE_DETECTED, SecurityAuditOutcome.FAILURE,
          presented.getUserId(), null,
          "family " + presented.getFamilyId() + " revoked; " + killed + " token(s) killed");
      throw new BadCredentialsException("Refresh token reuse detected");
    }

    if (!presented.getExpiresAt().isAfter(now)) {
      // Expired naturally. No family revocation; the user will re-login and get a fresh family.
      throw new BadCredentialsException("Refresh token expired");
    }

    final User user = userRepository.findById(presented.getUserId())
        .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));

    if (user.getStatus() == UserStatus.LOCKED) {
      // Same status mapping as login and JwtAuthenticationFilter: LOCKED is its own signal
      // (LockedException -> 423), never folded into the generic disabled 403. Deliberately NO
      // releaseExpiredLock here: a lockout is released by proving the password at /login, not by
      // replaying a session credential minted before the lock — once the window passes, a correct
      // password logs in and starts a fresh family.
      throw new LockedException("User account is locked");
    }
    if (user.getStatus() != UserStatus.ACTIVE) {
      // Account state changed since the token was issued (suspended, closed). Refuse rotation.
      // JwtAuthenticationFilter applies the same rule to access tokens on every request, so the
      // user is locked out within minutes anyway — this just closes the refresh path too.
      throw new DisabledException("User account is not active");
    }

    final Issued next = issue(presented.getUserId(), presented.getFamilyId(), clientIp, userAgent);

    // Walk the chain forward. save() returned the new entity with its generated id assigned.
    presented.setRevokedAt(now);
    presented.setReplacedByTokenId(next.entity().getId());
    // No explicit save() on presented — managed entity, dirty checking handles it on commit.

    return new RotatedTokens(next.rawToken(), next.entity().getExpiresAt(), presented.getUserId());
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public void revokeFamily(String rawRefreshToken) {
    if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
      return;
    }
    refreshTokenRepository.findByTokenHash(sha256Hex(rawRefreshToken))
        .ifPresent(rt -> {
          int revoked = refreshTokenRepository.revokeFamily(rt.getUserId(), rt.getFamilyId(), Instant.now());
          // LOGOUT audit only when a still-active token was actually revoked — never for an
          // unknown token (no existence oracle; RFC 7009 §2.2) and never for a re-presented,
          // already-dead family, which would append a duplicate LOGOUT row per retry without any
          // session having ended.
          if (revoked > 0) {
            securityAuditService.record(SecurityAuditEventType.LOGOUT, SecurityAuditOutcome.SUCCESS,
                rt.getUserId(), null, null);
          }
        });
    // Idempotent: logging out with an unknown token is a no-op. Do not leak existence.
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public void revokeAllForUser(Long userId) {
    refreshTokenRepository.revokeAllByUser(userId, Instant.now());
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public int deleteExpired(Instant cutoff) {
    return refreshTokenRepository.deleteByExpiresAtBefore(cutoff);
  }

  // -----------------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------------

  /**
   * Inserts a refresh-token row and returns it paired with the raw (unhashed) value the caller
   * must hand back to the client. The raw string is not part of the entity (we never store it),
   * so this internal record bundles them for callers that need both — like {@code rotate}, which
   * needs the new id to link the chain forward.
   */
  private Issued issue(Long userId, UUID familyId, String clientIp, String userAgent) {
    final byte[] raw = new byte[RAW_TOKEN_BYTES];
    SECURE_RANDOM.nextBytes(raw);
    final String rawEncoded = BASE64_URL.encodeToString(raw);
    final String hash = sha256Hex(rawEncoded);

    final Instant issuedAt = Instant.now();
    final Instant expiresAt = issuedAt.plus(securityProperties.refreshToken().expiration());

    RefreshToken row = RefreshToken.builder()
        .tokenHash(hash)
        .userId(userId)
        .familyId(familyId)
        .issuedAt(issuedAt)
        .expiresAt(expiresAt)
        .createdFromIp(truncate(clientIp, 45))
        .userAgent(truncate(userAgent, 255))
        .build();

    RefreshToken saved = refreshTokenRepository.save(row);
    return new Issued(rawEncoded, saved);
  }

  /** Internal pairing of raw-string + persisted row. Not exposed across the service boundary. */
  private record Issued(String rawToken, RefreshToken entity) {}

  /**
   * SHA-256 hex digest, same convention as {@code idempotency_keys.request_hash}. Fits in the
   * {@code VARCHAR(64)} column. Constant-time comparison is not relevant here: we look up BY
   * hash, we do not compare candidates against a known-good value.
   */
  private static String sha256Hex(String value) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException e) {
      // SHA-256 is mandated by every JRE since 1.4.2; this branch is theoretical.
      throw new IllegalStateException("SHA-256 algorithm not available", e);
    }
  }

  private static String truncate(String value, int maxLength) {
    if (value == null) {
      return null;
    }
    return value.length() <= maxLength ? value : value.substring(0, maxLength);
  }
}
