package com.jesusf.paydude.service;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.config.properties.SecurityProperties.Lockout;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.metrics.BusinessMetrics;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.support.SecurityPropertiesFixture;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link LoginAttemptServiceImpl}.
 *
 * <p>The actual locking decision lives in SQL (the {@code WHERE failed_login_attempts >= :max}
 * predicate), so it cannot be proven against a mocked repository — that is {@code AccountLockoutIT}'s
 * job, end-to-end on Postgres. What these tests pin is the <i>orchestration</i> the service owns: the
 * increment-then-lock ordering, the computed lockout window ({@code now + lockoutDuration}), the
 * lockout metric firing exactly when the transition happens, email canonicalisation, and the
 * enabled/disabled toggle short-circuiting every path.
 */
@ExtendWith(MockitoExtension.class)
class LoginAttemptServiceImplTest {

  private static final int MAX_ATTEMPTS = 5;
  private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);
  // The email arrives dirty (spaces + mixed case) to prove the service canonicalizes it before
  // touching the repository — exactly as the real login flow would.
  private static final String RAW_EMAIL = "  Jesus@Test.COM  ";
  private static final String CANONICAL_EMAIL = "jesus@test.com";

  @Mock private UserRepository userRepository;
  @Mock private BusinessMetrics metrics;
  @Mock private SecurityAuditService securityAuditService;

  private LoginAttemptServiceImpl serviceWithLockout(boolean enabled) {
    SecurityProperties properties = SecurityPropertiesFixture.withLockout(
        new Lockout(enabled, MAX_ATTEMPTS, LOCKOUT_DURATION));
    return new LoginAttemptServiceImpl(userRepository, properties, metrics, securityAuditService);
  }

  @Nested
  @DisplayName("recordFailure")
  class RecordFailure {

    @Test
    @DisplayName("Should increment, then lock at threshold with a now+duration window, and emit the metric")
    void shouldIncrementThenLockAndEmitMetric() {
      LoginAttemptServiceImpl service = serviceWithLockout(true);
      // The already-incremented counter reached the threshold: the lock UPDATE affects 1 row.
      when(userRepository.lockIfThresholdReached(eq(CANONICAL_EMAIL), eq(UserStatus.ACTIVE),
          eq(UserStatus.LOCKED), eq(MAX_ATTEMPTS), any(Instant.class))).thenReturn(1);

      Instant lowerBound = Instant.now().plus(LOCKOUT_DURATION);
      service.recordFailure(RAW_EMAIL);
      Instant upperBound = Instant.now().plus(LOCKOUT_DURATION);

      // The increment must precede the lock evaluation: on Postgres the second UPDATE sees the
      // incremented value within the same transaction.
      InOrder inOrder = inOrder(userRepository);
      inOrder.verify(userRepository).incrementFailedLoginAttempts(CANONICAL_EMAIL, UserStatus.ACTIVE);
      ArgumentCaptor<Instant> lockUntil = ArgumentCaptor.forClass(Instant.class);
      inOrder.verify(userRepository).lockIfThresholdReached(eq(CANONICAL_EMAIL), eq(UserStatus.ACTIVE),
          eq(UserStatus.LOCKED), eq(MAX_ATTEMPTS), lockUntil.capture());

      assertFalse(lockUntil.getValue().isBefore(lowerBound), "lockout window must be >= now + duration");
      assertFalse(lockUntil.getValue().isAfter(upperBound), "lockout window must be <= now + duration");
      verify(metrics).recordAccountLocked();
      // The audit row carries no userId: the lock is an atomic UPDATE by email — the entity is
      // never loaded.
      verify(securityAuditService).record(eq(SecurityAuditEventType.ACCOUNT_LOCKED),
          eq(SecurityAuditOutcome.FAILURE), isNull(), eq(CANONICAL_EMAIL), anyString());
    }

    @Test
    @DisplayName("Should not emit the lockout metric when the threshold is not yet reached")
    void shouldNotEmitMetricBelowThreshold() {
      LoginAttemptServiceImpl service = serviceWithLockout(true);
      when(userRepository.lockIfThresholdReached(anyString(), any(), any(), anyInt(), any(Instant.class)))
          .thenReturn(0);

      service.recordFailure(RAW_EMAIL);

      verify(userRepository).incrementFailedLoginAttempts(CANONICAL_EMAIL, UserStatus.ACTIVE);
      verify(metrics, never()).recordAccountLocked();
      // No lock transition, no ACCOUNT_LOCKED audit event.
      verify(securityAuditService, never()).record(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Should be a no-op when lockout is disabled")
    void shouldNoOpWhenDisabled() {
      serviceWithLockout(false).recordFailure(RAW_EMAIL);
      verifyNoInteractions(userRepository, metrics, securityAuditService);
    }
  }

  @Nested
  @DisplayName("recordSuccess")
  class RecordSuccess {

    @Test
    @DisplayName("Should reset the user's failure counter when enabled")
    void shouldResetCounter() {
      serviceWithLockout(true).recordSuccess(42L);
      verify(userRepository).resetFailedLoginAttempts(42L);
    }

    @Test
    @DisplayName("Should be a no-op when lockout is disabled")
    void shouldNoOpWhenDisabled() {
      serviceWithLockout(false).recordSuccess(42L);
      verifyNoInteractions(userRepository, metrics, securityAuditService);
    }
  }

  @Nested
  @DisplayName("releaseExpiredLock")
  class ReleaseExpiredLock {

    @Test
    @DisplayName("Should return true and canonicalise the email when an expired lock is released")
    void shouldReleaseExpired() {
      LoginAttemptServiceImpl service = serviceWithLockout(true);
      when(userRepository.releaseExpiredLock(eq(CANONICAL_EMAIL), eq(UserStatus.ACTIVE),
          eq(UserStatus.LOCKED), any(Instant.class))).thenReturn(1);

      assertTrue(service.releaseExpiredLock(RAW_EMAIL));
    }

    @Test
    @DisplayName("Should return false when no expired lock matched")
    void shouldReturnFalseWhenNothingReleased() {
      LoginAttemptServiceImpl service = serviceWithLockout(true);
      when(userRepository.releaseExpiredLock(anyString(), any(), any(), any(Instant.class)))
          .thenReturn(0);

      assertFalse(service.releaseExpiredLock(RAW_EMAIL));
    }

    @Test
    @DisplayName("Should be a no-op returning false when lockout is disabled")
    void shouldNoOpWhenDisabled() {
      assertFalse(serviceWithLockout(false).releaseExpiredLock(RAW_EMAIL));
      verifyNoInteractions(userRepository, metrics, securityAuditService);
    }
  }
}
