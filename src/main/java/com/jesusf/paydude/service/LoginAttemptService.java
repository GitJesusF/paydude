package com.jesusf.paydude.service;

/**
 * Persistent, per-account anti-bruteforce lockout — the durable second line behind the in-memory
 * {@code AuthRateLimiter} (which throttles login attempts per email in a token bucket).
 *
 * <p>Where the rate limiter is volatile (resets on restart, keyed only by IP/email, refilled on a
 * timer), this service records consecutive failures on the {@code users} row itself and, once the
 * configured threshold is reached, transitions the account into {@link
 * com.jesusf.paydude.enums.UserStatus#LOCKED} for a cooldown window. That state is then enforced by
 * the existing {@code SecurityUser.isAccountNonLocked()} check, which raises {@code LockedException}
 * (HTTP 423) on the next attempt.
 *
 * <p><b>Temporary, not permanent.</b> The lock carries an expiry; {@link #releaseExpiredLock(String)}
 * lifts it once the window elapses. Permanent ("contact support") lockout is deliberately avoided —
 * it is a self-inflicted denial-of-service vector, since anyone who knows a victim's email could
 * lock them out at will by failing logins. This matches OWASP ASVS V2.2 and NIST SP 800-63B §5.2.2,
 * which favour throttling/temporary lockout over permanent.
 *
 * <p>All three operations are no-ops when {@code application.security.lockout.enabled} is false, and
 * each runs in its own {@code REQUIRES_NEW} transaction so the failure count commits even though the
 * surrounding login transaction unwinds with an {@code AuthenticationException}.
 *
 * @see com.jesusf.paydude.security.ratelimit.AuthRateLimiter
 */
public interface LoginAttemptService {

  /**
   * Records one failed login for the account with this email and locks it if the consecutive-failure
   * threshold is now reached. A no-op (matching zero rows, no lock, no metric) for an unknown email,
   * so it never becomes an account-enumeration oracle.
   *
   * @param email the submitted login email (canonicalised internally)
   */
  void recordFailure(String email);

  /**
   * Resets the consecutive-failure counter after a successful login. A no-op when there is nothing
   * to clear, so a clean login adds no write.
   *
   * @param userId the id of the user that just authenticated
   */
  void recordSuccess(Long userId);

  /**
   * Clears a <em>temporary</em> lock whose window has elapsed, returning the account to
   * {@code ACTIVE} so the caller can retry authentication. Leaves a permanent/administrative lock
   * (a {@code LOCKED} row with no expiry) untouched.
   *
   * @param email the submitted login email (canonicalised internally)
   * @return {@code true} if an expired lock was released, {@code false} otherwise
   */
  boolean releaseExpiredLock(String email);
}
