package com.jesusf.paydude.service;

import com.jesusf.paydude.entity.RefreshToken;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.Role;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.repository.RefreshTokenRepository;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.service.RefreshTokenService.IssuedRefreshToken;
import com.jesusf.paydude.service.RefreshTokenService.RotatedTokens;
import com.jesusf.paydude.support.TestcontainersConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.ActiveProfiles;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Integration coverage for refresh-token reuse detection.
 *
 * <p>The unit test can verify that the revocation collaborator is invoked, but only a real Spring
 * transaction can prove the security side effect survives the {@code BadCredentialsException}
 * thrown back to the client.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class RefreshTokenReuseDetectionIT {

  private static final String CLIENT_IP = "203.0.113.42";
  private static final String USER_AGENT = "PayDudeReuseDetectionIT/1.0";

  @Autowired private RefreshTokenService refreshTokenService;
  @Autowired private RefreshTokenRepository refreshTokenRepository;
  @Autowired private UserRepository userRepository;

  @Test
  @DisplayName("Reuse detection commits family revocation even though rotate rejects the request")
  void reuseDetectionCommitsFamilyRevocation() {
    User user = userRepository.save(User.builder()
        .firstName("Reuse")
        .lastName("Detection")
        .email("reuse-" + UUID.randomUUID() + "@test.com")
        .password("$2a$10$unusedHashOnlyNeededForNotNullColumn")
        .role(Role.ROLE_USER)
        .status(UserStatus.ACTIVE)
        .passwordChangedAt(Instant.now())
        .build());

    // T1 is born active; the first legitimate rotation revokes T1 and creates T2 in the same family.
    IssuedRefreshToken first = refreshTokenService.issueNewFamily(user.getId(), CLIENT_IP, USER_AGENT);
    RotatedTokens second = refreshTokenService.rotate(first.rawToken(), CLIENT_IP, USER_AGENT);

    RefreshToken activeSuccessor = refreshTokenRepository.findByTokenHash(sha256Hex(second.rawRefreshToken()))
        .orElseThrow();
    assertNull(activeSuccessor.getRevokedAt(), "successor token must be active before reuse detection");

    BadCredentialsException ex = assertThrows(
        BadCredentialsException.class,
        () -> refreshTokenService.rotate(first.rawToken(), CLIENT_IP, USER_AGENT)
    );
    assertEquals("Refresh token reuse detected", ex.getMessage());

    RefreshToken killedSuccessor = refreshTokenRepository.findByTokenHash(sha256Hex(second.rawRefreshToken()))
        .orElseThrow();
    assertNotNull(
        killedSuccessor.getRevokedAt(),
        "reuse detection must commit family revocation even after BadCredentialsException"
    );
  }

  private static String sha256Hex(String value) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes());
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 algorithm not available", e);
    }
  }
}
