package com.jesusf.paydude.service;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.dto.auth.AuthResponse;
import com.jesusf.paydude.dto.auth.LoginRequest;
import com.jesusf.paydude.dto.auth.LoginResult;
import com.jesusf.paydude.dto.auth.RegisterRequest;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.support.TestcontainersConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Integration coverage for the account-lockout anti-bruteforce flow.
 *
 * <p>The unit tests pin the orchestration ({@code AuthServiceTest}, {@code LoginAttemptServiceImplTest}),
 * but only a real Spring transaction against Postgres can prove the parts that live in SQL and in the
 * {@code DaoAuthenticationProvider} pre-authentication check: that the counter actually crosses the
 * threshold, that {@code UserStatus.LOCKED} then yields {@code LockedException} (HTTP 423) ahead of the
 * password check, and that an elapsed window auto-releases the lock.
 *
 * <p><b>Why this drives {@code AuthService} directly instead of {@code POST /v1/auth/login}.</b> The
 * controller consumes {@code AuthRateLimiter}'s per-email bucket (capacity 5) before delegating, so an
 * HTTP-level test would trip a {@code 429} around the same count the lockout trips a {@code 423} —
 * masking the very behaviour under test. The two defences are intentionally independent (volatile
 * per-email rate limit vs. persistent per-account lockout); exercising the service isolates the lockout
 * exactly as {@code RefreshTokenReuseDetectionIT} isolates rotation.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class AccountLockoutIT {

  private static final String CLIENT_IP = "203.0.113.42";
  private static final String USER_AGENT = "PayDudeAccountLockoutIT/1.0";
  private static final String CORRECT_PASSWORD = "correct-horse-battery";
  private static final String WRONG_PASSWORD = "wrong-password";

  @Autowired private AuthService authService;
  @Autowired private UserRepository userRepository;
  @Autowired private SecurityProperties securityProperties;

  @Test
  @DisplayName("Locks after the threshold (423 on the next attempt) and auto-unlocks once the window elapses")
  void shouldLockAfterThresholdThenAutoUnlock() {
    String email = "lockout-" + UUID.randomUUID() + "@test.com";
    authService.register(new RegisterRequest("Lock", "Out", email, CORRECT_PASSWORD), CLIENT_IP, USER_AGENT);

    int maxAttempts = securityProperties.lockout().maxAttempts();

    // 1) maxAttempts wrong passwords. All of them return BadCredentials (401): the lock is
    //    applied after the threshold-crossing attempt has already thrown.
    for (int i = 0; i < maxAttempts; i++) {
      assertThrows(BadCredentialsException.class,
          () -> authService.login(new LoginRequest(email, WRONG_PASSWORD), CLIENT_IP, USER_AGENT),
          "every wrong password returns BadCredentials; the lock is applied after the exception");
    }

    User locked = userRepository.findByEmail(email).orElseThrow();
    assertEquals(UserStatus.LOCKED, locked.getStatus(), "account must be LOCKED once the threshold is crossed");
    assertEquals(maxAttempts, locked.getFailedLoginAttempts());
    assertNotNull(locked.getLockoutExpiresAt(), "a temporary lock must carry an auto-release expiry");

    // 2) The next attempt — even with the CORRECT password — is rejected with LockedException
    //    (HTTP 423): the account is locked and the password is never even evaluated.
    assertThrows(LockedException.class,
        () -> authService.login(new LoginRequest(email, CORRECT_PASSWORD), CLIENT_IP, USER_AGENT),
        "a locked account is rejected with LockedException before the password is checked");

    // 3) Backdate the lock window instead of waiting on the real clock.
    locked.setLockoutExpiresAt(Instant.now().minusSeconds(60));
    userRepository.save(locked);

    // 4) A correct login now releases the lock (releaseExpiredLock), authenticates, and resets
    //    the account state.
    AuthResponse response = loginTokens(email, CORRECT_PASSWORD);
    assertNotNull(response.accessToken(), "a correct login after the window elapses must succeed");

    User unlocked = userRepository.findByEmail(email).orElseThrow();
    assertEquals(UserStatus.ACTIVE, unlocked.getStatus(), "an expired lock must auto-release back to ACTIVE");
    assertEquals(0, unlocked.getFailedLoginAttempts(), "unlocking resets the consecutive-failure counter");
    assertNull(unlocked.getLockoutExpiresAt(), "unlocking clears the expiry");
  }

  @Test
  @DisplayName("A successful login below the threshold resets the consecutive-failure counter")
  void shouldResetCounterOnSuccessfulLoginBelowThreshold() {
    String email = "reset-" + UUID.randomUUID() + "@test.com";
    authService.register(new RegisterRequest("Reset", "Counter", email, CORRECT_PASSWORD), CLIENT_IP, USER_AGENT);

    int maxAttempts = securityProperties.lockout().maxAttempts();

    // Fail (maxAttempts - 1) times: failures accumulate but the threshold is never crossed.
    for (int i = 0; i < maxAttempts - 1; i++) {
      assertThrows(BadCredentialsException.class,
          () -> authService.login(new LoginRequest(email, WRONG_PASSWORD), CLIENT_IP, USER_AGENT));
    }
    assertEquals(maxAttempts - 1, userRepository.findByEmail(email).orElseThrow().getFailedLoginAttempts(),
        "consecutive failures accumulate while below the threshold");

    // A correct login resets the counter to 0 and the account stays ACTIVE — the next failure
    // starts from scratch, so a legitimate user who occasionally fumbles never approaches the lock.
    assertNotNull(loginTokens(email, CORRECT_PASSWORD).accessToken());

    User afterSuccess = userRepository.findByEmail(email).orElseThrow();
    assertEquals(0, afterSuccess.getFailedLoginAttempts(), "a successful login clears accumulated failures");
    assertEquals(UserStatus.ACTIVE, afterSuccess.getStatus());
  }

  // Login expecting the Tokens branch of the sealed LoginResult. Users in this IT are created
  // via register (no MFA), so an MfaRequired here would be a test failure.
  private AuthResponse loginTokens(String email, String password) {
    LoginResult result = authService.login(new LoginRequest(email, password), CLIENT_IP, USER_AGENT);
    return ((LoginResult.Tokens) result).tokens();
  }
}
