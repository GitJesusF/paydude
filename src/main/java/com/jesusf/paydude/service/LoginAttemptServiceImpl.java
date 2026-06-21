package com.jesusf.paydude.service;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.metrics.BusinessMetrics;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.util.EmailNormalizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Default {@link LoginAttemptService} implementation, backed by atomic SQL UPDATEs on the
 * {@code users} row.
 *
 * <p>Every mutation is a single statement (increment, conditional lock, conditional release,
 * conditional reset). That choice is deliberate: a read-modify-write would let two concurrent failed
 * logins read the same count and both write {@code n+1}, losing an increment — and under contention
 * could even fork the lock decision. Pushing the predicate into the {@code WHERE} clause makes each
 * operation race-safe without taking a pessimistic row lock on the hot login path.
 *
 * <p>The class is {@code @Transactional(readOnly = true)} by default, but each write method runs in
 * {@code REQUIRES_NEW}: the login transaction that calls {@code recordFailure} is about to unwind
 * with a {@code BadCredentialsException}, so the failure count must commit in its own transaction or
 * it would roll back with the rejected login and the counter would never move (same isolation
 * pattern as {@code IdempotencyKeyServiceImpl}).
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class LoginAttemptServiceImpl implements LoginAttemptService {

  private final UserRepository userRepository;
  private final SecurityProperties securityProperties;
  private final BusinessMetrics metrics;
  // Persists the ACCOUNT_LOCKED event (with the targeted email) to the security audit log when the
  // threshold trips. record(...) is itself REQUIRES_NEW + fail-safe, so it never breaks this flow.
  private final SecurityAuditService securityAuditService;

  @Override
  @Transactional(propagation = Propagation.REQUIRES_NEW, rollbackFor = Exception.class)
  public void recordFailure(String email) {
    SecurityProperties.Lockout lockout = securityProperties.lockout();
    if (!lockout.enabled()) {
      return;
    }
    String canonicalEmail = EmailNormalizer.normalize(email);

    // 1) Increment the counter, but only for ACTIVE accounts. An unknown email matches 0 rows, so
    //    this method neither confirms nor denies that the account exists (no enumeration oracle) —
    //    the caller sees the same 401 either way.
    userRepository.incrementFailedLoginAttempts(canonicalEmail, UserStatus.ACTIVE);

    // 2) Lock if the just-incremented counter has reached the threshold. Within one transaction
    //    Postgres sees the previous UPDATE's effect, so the comparison runs against the new value.
    Instant lockoutExpiresAt = Instant.now().plus(lockout.lockoutDuration());
    int locked = userRepository.lockIfThresholdReached(
        canonicalEmail, UserStatus.ACTIVE, UserStatus.LOCKED, lockout.maxAttempts(), lockoutExpiresAt);

    if (locked > 0) {
      metrics.recordAccountLocked();
      // paydude.auth.lockout is the credential-stuffing signal on the Grafana dashboards; the
      // application log stays free of PII (no email, no id). The targeted identity (the email)
      // is persisted in the security audit log below, not in the application log — a different
      // threat model: the audit table is admin-only.
      log.warn("Account locked after {} consecutive failed login attempts (lockout window: {})",
          lockout.maxAttempts(), lockout.lockoutDuration());
      securityAuditService.record(SecurityAuditEventType.ACCOUNT_LOCKED, SecurityAuditOutcome.FAILURE,
          null, canonicalEmail,
          "locked after " + lockout.maxAttempts() + " consecutive failures (window " + lockout.lockoutDuration() + ")");
    }
  }

  @Override
  @Transactional(propagation = Propagation.REQUIRES_NEW, rollbackFor = Exception.class)
  public void recordSuccess(Long userId) {
    if (!securityProperties.lockout().enabled()) {
      return;
    }
    // The WHERE skips already-clean accounts, so a successful login with no prior failures
    // matches 0 rows: the happy path never pays a real write.
    userRepository.resetFailedLoginAttempts(userId);
  }

  @Override
  @Transactional(propagation = Propagation.REQUIRES_NEW, rollbackFor = Exception.class)
  public boolean releaseExpiredLock(String email) {
    if (!securityProperties.lockout().enabled()) {
      return false;
    }
    String canonicalEmail = EmailNormalizer.normalize(email);
    // Releases only TEMPORARY locks whose window has passed (status=LOCKED with a non-null, past
    // lockout_expires_at). A permanent administrative lock (null lockout_expires_at) does not
    // match the UPDATE and stays in place.
    int released = userRepository.releaseExpiredLock(
        canonicalEmail, UserStatus.ACTIVE, UserStatus.LOCKED, Instant.now());
    return released > 0;
  }
}
