package com.jesusf.paydude.security;

import com.jesusf.paydude.exception.BusinessException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.stereotype.Component;

/**
 * Screens a chosen password against the HaveIBeenPwned breach corpus before it is accepted at
 * registration or password rotation — NIST SP 800-63B §5.1.1.2 ("verifiers SHALL compare the
 * prospective secret against a list of values known to be compromised").
 *
 * <p>The raw password never leaves the JVM: the underlying {@link CompromisedPasswordChecker}
 * hashes it with SHA-1 and sends only the first five hex characters of the digest to the range
 * API (k-anonymity), then matches the returned suffixes locally.
 *
 * <p>This guard wraps the checker bean with two policy decisions the raw checker does not make on
 * its own:
 * <ul>
 *   <li><b>Fail-open.</b> If the HaveIBeenPwned API is unreachable, the check is skipped (logged
 *       at WARN) rather than blocking the user. A third-party outage must not take down signup or
 *       password changes — the industry-standard graceful-degradation posture for breach checks.</li>
 *   <li><b>Domain exception.</b> A compromised password surfaces as a {@link BusinessException}
 *       (HTTP 409), so it travels the same per-concern advice path and {@code ProblemDetail} shape
 *       as every other domain-rule rejection — no second error format leaks to clients.</li>
 * </ul>
 *
 * <p>Whether the live checker or a no-op is wired is decided by
 * {@code application.security.password.breach-check-enabled} — see
 * {@code SecurityConfig#compromisedPasswordChecker}.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BreachedPasswordGuard {

  private final CompromisedPasswordChecker compromisedPasswordChecker;

  /**
   * Rejects the password if it is present in the breach corpus.
   *
   * @param rawPassword the plaintext password the caller chose
   * @throws BusinessException if the password is found in a known data breach
   */
  public void assertNotBreached(String rawPassword) {
    boolean compromised;
    try {
      compromised = compromisedPasswordChecker.check(rawPassword).isCompromised();
    } catch (RuntimeException e) {
      // Fail-open: a HaveIBeenPwned outage must not block registration or password rotation.
      log.warn("Breached-password check skipped — HaveIBeenPwned API unavailable: {}", e.getMessage());
      return;
    }
    if (compromised) {
      // The password itself is never logged — no PII, no credential material in the log line.
      log.warn("Password rejected — present in a known data-breach corpus (HaveIBeenPwned)");
      throw new BusinessException(
          "This password has appeared in a known data breach. Please choose a different one.");
    }
  }
}