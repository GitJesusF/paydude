package com.jesusf.paydude.service;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.dto.auth.AuthResponse;
import com.jesusf.paydude.dto.auth.LoginRequest;
import com.jesusf.paydude.dto.auth.LoginResult;
import com.jesusf.paydude.dto.auth.MfaChallengeResponse;
import com.jesusf.paydude.dto.auth.MfaVerifyRequest;
import com.jesusf.paydude.dto.auth.RegisterRequest;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.Role;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.event.UserRegisteredEvent;
import com.jesusf.paydude.exception.BusinessException;
import com.jesusf.paydude.metrics.BusinessMetrics;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.security.BreachedPasswordGuard;
import com.jesusf.paydude.security.JwtClaimNames;
import com.jesusf.paydude.security.JwtService;
import com.jesusf.paydude.security.SecurityUser;
import com.jesusf.paydude.service.MfaService.MfaVerification;
import com.jesusf.paydude.service.RefreshTokenService.IssuedRefreshToken;
import com.jesusf.paydude.service.RefreshTokenService.RotatedTokens;
import com.jesusf.paydude.util.EmailNormalizer;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Default {@link AuthService} implementation.
 *
 * <p>Login is tuned to a single DB read end-to-end: {@code DaoAuthenticationProvider} loads the
 * user once through {@code CustomUserDetailsService} and exposes the {@link SecurityUser}
 * projection as the {@code Authentication} principal, which already carries everything the JWT
 * needs. Registration and refresh additionally write a refresh-token family. Every token-minting
 * path emits a {@code paydude.auth.*} metric.
 *
 * <p>The class is {@code @Transactional(readOnly = true)}; the write paths ({@code register},
 * {@code refresh}, {@code logout}) override that.
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthServiceImpl implements AuthService {

  private static final String BEARER_TOKEN_TYPE = "Bearer";

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;
  private final ApplicationEventPublisher eventPublisher;
  // Same SecurityProperties bean injected into CustomUserDetailsService — guarantees that the
  // credential rotation window enforced at login matches the one embedded in the JWT claim.
  private final SecurityProperties securityProperties;
  private final BusinessMetrics metrics;
  private final RefreshTokenService refreshTokenService;
  private final BreachedPasswordGuard breachedPasswordGuard;
  // Persistent anti-bruteforce lockout — the durable second line behind AuthController's per-email
  // AuthRateLimiter. No-op internally when application.security.lockout.enabled is false.
  private final LoginAttemptService loginAttemptService;
  // Append-only security audit trail (security_audit_events) — records the login/register outcomes
  // below. record(...) is durable (REQUIRES_NEW) and fail-safe, so it never breaks the auth flow.
  private final SecurityAuditService securityAuditService;
  // Verifies the TOTP/recovery proof during the step-up login. Token minting stays HERE — the MFA
  // service owns codes and enrollment, never sessions.
  private final MfaService mfaService;

  @Override
  @Transactional(rollbackFor = Exception.class)
  public AuthResponse register(RegisterRequest request, String clientIp, String userAgent) {
    String email = EmailNormalizer.normalize(request.email());

    if (userRepository.existsByEmail(email)) {
      throw new BusinessException("Email already exists");
    }

    // Reject passwords already exposed in a public breach corpus (NIST SP 800-63B §5.1.1.2).
    // Checked after the email lookup so a duplicate-email attempt never spends a HaveIBeenPwned
    // round-trip; fails open if the API is down (see BreachedPasswordGuard).
    breachedPasswordGuard.assertNotBreached(request.password());

    User user = User.builder()
        .firstName(request.firstName())
        .lastName(request.lastName())
        .email(email)
        .password(passwordEncoder.encode(request.password()))
        .role(Role.ROLE_USER)
        .passwordChangedAt(Instant.now())
        .build();

    User savedUser = userRepository.save(user);
    eventPublisher.publishEvent(new UserRegisteredEvent(savedUser.getId()));

    SecurityUser principal = SecurityUser.fromEntity(savedUser, securityProperties.credentialsExpirationDays());
    IssuedRefreshToken refresh = refreshTokenService.issueNewFamily(savedUser.getId(), clientIp, userAgent);
    AuthResponse response = buildAuthResponse(principal, refresh);
    metrics.recordRegister();
    securityAuditService.record(SecurityAuditEventType.REGISTER, SecurityAuditOutcome.SUCCESS,
        savedUser.getId(), email, null);
    return response;
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public LoginResult login(LoginRequest request, String clientIp, String userAgent) {
    // Read-write: a successful login WRITES a refresh-token row via issueNewFamily (propagation
    // REQUIRED, so it joins this transaction). Without the override, login would inherit the
    // class-level readOnly=true and the refresh-token INSERT would fail on a read-only connection.
    // The failed-attempt counters in LoginAttemptService run in their own REQUIRES_NEW transactions,
    // so they still commit even when this transaction unwinds with an AuthenticationException.
    String email = EmailNormalizer.normalize(request.email());

    // Anti-bruteforce, persistent second line (after AuthController's per-email rate limit): if a
    // TEMPORARY lock's window has already elapsed, release it BEFORE authenticating so a correct
    // password logs in on this same request. A single-row UPDATE that matches nothing for an
    // unlocked account or a permanent admin lock — and an immediate no-op when lockout is disabled,
    // preserving login's single-DB-read profile.
    loginAttemptService.releaseExpiredLock(email);

    // DaoAuthenticationProvider loads the user once through CustomUserDetailsService and exposes
    // the SecurityUser projection as the Authentication principal. Everything we need to issue
    // the token (id, role, status, expirations) lives on that principal, so the credential check
    // is a single DB read.
    //
    // Failure handling is split by cause:
    //   - BadCredentialsException = wrong password on an ACTIVE account (or unknown email): count
    //     it; the count locks the account once it reaches the threshold, so the NEXT attempt gets
    //     LockedException (423) while this one stays 401.
    //   - any other AuthenticationException (LockedException within its window, Disabled,
    //     AccountExpired, CredentialsExpired) is not a wrong password, so it must NOT feed the
    //     brute-force counter — only the paydude.auth.login{outcome=failure} metric.
    Authentication auth;
    try {
      auth = authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(email, request.password())
      );
    } catch (BadCredentialsException e) {
      loginAttemptService.recordFailure(email);
      metrics.recordLogin(false);
      // Wrong password (or unknown email) — record the attempt against the targeted identity.
      securityAuditService.record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE,
          null, email, "bad credentials");
      throw e;
    } catch (AuthenticationException e) {
      metrics.recordLogin(false);
      // Not a wrong password: a degraded account state (locked within its window, disabled, expired).
      // The exception type is non-sensitive and tells an investigator WHY the login was refused.
      securityAuditService.record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE,
          null, email, e.getClass().getSimpleName());
      throw e;
    }

    SecurityUser principal = (SecurityUser) auth.getPrincipal();

    // Step-up: for an MFA-enrolled account a correct password earns a challenge, not a session.
    // Deliberately NO recordSuccess, NO login metric, NO refresh family here — the login is not
    // complete. Resetting the failure counter at this stage would hand an attacker who knows the
    // password `max-attempts` fresh TOTP guesses per challenge cycle; by deferring the reset to
    // verifyMfa, failed codes accumulate across cycles and trip the same lockout as failed
    // passwords. The MFA_CHALLENGE audit row is the forensic marker: a challenge with no
    // subsequent LOGIN/SUCCESS means a compromised password was stopped by the second factor.
    if (principal.mfaEnabled()) {
      String challengeToken = jwtService.generateMfaChallengeToken(principal.id());
      securityAuditService.record(SecurityAuditEventType.MFA_CHALLENGE, SecurityAuditOutcome.SUCCESS,
          principal.id(), email, "password verified; second factor pending");
      return new LoginResult.MfaRequired(new MfaChallengeResponse(
          true, challengeToken, jwtService.getMfaChallengeExpirationSeconds()));
    }

    // Successful login resets the consecutive-failure counter (a no-op when it was already clean).
    loginAttemptService.recordSuccess(principal.id());
    IssuedRefreshToken refresh = refreshTokenService.issueNewFamily(principal.id(), clientIp, userAgent);
    AuthResponse response = buildAuthResponse(principal, refresh);
    metrics.recordLogin(true);
    securityAuditService.record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.SUCCESS,
        principal.id(), email, null);
    return new LoginResult.Tokens(response);
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public AuthResponse verifyMfa(MfaVerifyRequest request, String clientIp, String userAgent) {
    // Read-write for the same reason as login: the happy path writes a refresh-token row.
    //
    // 1. The challenge token is the proof that THIS user passed the password stage minutes ago.
    // parseMfaChallengeClaims enforces typ=mfa+jwt, so an access token (or any other JWT we ever
    // mint) can never stand in for that proof. Signature/expiry failures collapse into the same
    // generic 401 as a wrong code — no oracle about which part failed.
    Claims claims;
    try {
      claims = jwtService.parseMfaChallengeClaims(request.mfaToken());
    } catch (JwtException | IllegalArgumentException e) {
      metrics.recordMfaVerification(false);
      securityAuditService.record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE,
          null, null, "invalid mfa challenge token");
      throw new BadCredentialsException("Invalid or expired MFA challenge", e);
    }

    // 2. Account state is re-read from the DB, not trusted from the challenge (which is why the
    // challenge carries no status claim): five minutes is plenty of time to get locked or
    // suspended, and unlike the access-token hot path this flow runs once per login.
    //
    // Every refusal below mirrors the invalid-token/invalid-code branches: a failed-verification
    // metric plus a LOGIN/FAILURE audit row whose detail names the cause — otherwise some MFA
    // failure modes would be invisible to the dashboards and the forensic walk-back.
    Long userId = jwtService.extractUserId(claims);
    User user = userRepository.findById(userId).orElse(null);
    if (user == null) {
      // A validly-signed challenge for a user row that no longer exists (deleted mid-challenge).
      metrics.recordMfaVerification(false);
      securityAuditService.record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE,
          userId, null, "mfa challenge for unknown user");
      throw new BadCredentialsException("Invalid or expired MFA challenge");
    }

    // Failed MFA attempts feed the lockout, so the lock can trip — and expire — mid-flow. Honour
    // the temporary-lock contract here exactly like login does before authenticating. The release
    // is a committed REQUIRES_NEW UPDATE that bypasses the persistence context; the loaded entity
    // is deliberately NOT mutated to match (a dirty flush would write every column back with
    // stale in-memory values, clobbering the released counter) — the post-release state is
    // carried in effectiveStatus and applied to the principal below.
    boolean releasedExpiredLock = user.getStatus() == UserStatus.LOCKED
        && loginAttemptService.releaseExpiredLock(user.getEmail());
    UserStatus effectiveStatus = releasedExpiredLock ? UserStatus.ACTIVE : user.getStatus();
    // Same exception/status mapping as the UserDetails contract: LOCKED → 423, other non-ACTIVE →
    // 403 — a degraded account must answer identically whether it fails at the password or here.
    // The audit detail carries the exception's simple name, matching the vocabulary login uses
    // for its caught AuthenticationExceptions.
    if (effectiveStatus == UserStatus.LOCKED) {
      metrics.recordMfaVerification(false);
      securityAuditService.record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE,
          user.getId(), user.getEmail(), LockedException.class.getSimpleName());
      throw new LockedException("User account is locked");
    }
    if (effectiveStatus != UserStatus.ACTIVE) {
      metrics.recordMfaVerification(false);
      securityAuditService.record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE,
          user.getId(), user.getEmail(), DisabledException.class.getSimpleName());
      throw new DisabledException("User account is not active");
    }
    if (!user.isMfaEnabled()) {
      // MFA was disabled between challenge and verify — the challenge no longer means anything.
      metrics.recordMfaVerification(false);
      securityAuditService.record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE,
          user.getId(), user.getEmail(), "mfa no longer enabled at verify");
      throw new BadCredentialsException("Invalid or expired MFA challenge");
    }

    // 3. The code itself. INVALID is a failed authentication, with the same side-effects as a
    // wrong password: persistent failure count (recordFailure can flip the account to LOCKED in
    // its REQUIRES_NEW transaction, surviving this rollback), metric, audit row, generic 401.
    MfaVerification verification = mfaService.verify(user, request.code());
    if (verification == MfaVerification.INVALID) {
      loginAttemptService.recordFailure(user.getEmail());
      metrics.recordMfaVerification(false);
      securityAuditService.record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE,
          user.getId(), user.getEmail(), "invalid mfa code");
      throw new BadCredentialsException("Invalid MFA code");
    }

    // 4. Both factors proven — only now does the login complete: counter reset, session family,
    // login metric and the LOGIN/SUCCESS audit row (whose detail records WHICH second factor —
    // a redeemed recovery code is worth noticing in a forensic walk-back).
    loginAttemptService.recordSuccess(user.getId());
    SecurityUser principal = principalFor(user, releasedExpiredLock);
    IssuedRefreshToken refresh = refreshTokenService.issueNewFamily(user.getId(), clientIp, userAgent);
    AuthResponse response = buildAuthResponse(principal, refresh);
    metrics.recordMfaVerification(true);
    metrics.recordLogin(true);
    securityAuditService.record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.SUCCESS,
        user.getId(), user.getEmail(),
        verification == MfaVerification.RECOVERY_CODE ? "mfa: recovery code" : "mfa: totp");
    return response;
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public AuthResponse refresh(String rawRefreshToken, String clientIp, String userAgent) {
    // Rotation is the cold path: one DB read for the row lock, one save for the new token, one
    // dirty-check update for the previous row, one read for the user. Mint cost is dominated by
    // the lookup-and-rebuild of SecurityUser rather than by any cryptography.
    RotatedTokens rotated = refreshTokenService.rotate(rawRefreshToken, clientIp, userAgent);

    User user = userRepository.findById(rotated.userId())
        .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));
    SecurityUser principal = SecurityUser.fromEntity(user, securityProperties.credentialsExpirationDays());

    String accessToken = generateToken(principal);
    return new AuthResponse(
        accessToken,
        BEARER_TOKEN_TYPE,
        jwtService.getExpirationSeconds(),
        rotated.rawRefreshToken(),
        refreshExpirationSeconds()
    );
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public void logout(String rawRefreshToken) {
    refreshTokenService.revokeFamily(rawRefreshToken);
  }

  // -----------------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------------

  /**
   * Principal for the MFA-completed login. When this very request released an expired lock, the
   * entity still reads {@code LOCKED} (the release was a committed bulk UPDATE the persistence
   * context never saw), but the JWT must carry {@code ACTIVE} — embedding the stale status would
   * have {@code JwtAuthenticationFilter} reject every request of the fresh session with a 423.
   */
  private SecurityUser principalFor(User user, boolean releasedExpiredLock) {
    SecurityUser principal = SecurityUser.fromEntity(user, securityProperties.credentialsExpirationDays());
    if (!releasedExpiredLock) {
      return principal;
    }
    return new SecurityUser(principal.id(), principal.email(), principal.password(),
        UserStatus.ACTIVE, principal.accountExpiresAt(), principal.credentialsExpireAt(),
        principal.mfaEnabled(), principal.authorities());
  }

  private AuthResponse buildAuthResponse(SecurityUser principal, IssuedRefreshToken refresh) {
    String token = generateToken(principal);
    return new AuthResponse(
        token,
        BEARER_TOKEN_TYPE,
        jwtService.getExpirationSeconds(),
        refresh.rawToken(),
        refreshExpirationSeconds()
    );
  }

  private long refreshExpirationSeconds() {
    return securityProperties.refreshToken().expiration().getSeconds();
  }

  private String generateToken(SecurityUser principal) {
    Map<String, Object> extraClaims = new HashMap<>();
    extraClaims.put(JwtClaimNames.STATUS, principal.status().name());
    principal.getAuthorities().stream()
        .findFirst()
        .ifPresent(authority -> extraClaims.put(JwtClaimNames.ROLE, authority.getAuthority()));

    // Expiry claims are embedded in the token so JwtAuthenticationFilter can enforce them on
    // every request without a DB hit. Omitted entirely when the feature is off, so legacy tokens
    // stay compatible and the JSON payload stays minimal.
    if (principal.accountExpiresAt() != null) {
      extraClaims.put(JwtClaimNames.ACCOUNT_EXPIRES_AT, principal.accountExpiresAt().toEpochMilli());
    }
    // Credential rotation window is off by default (NIST SP 800-63B). SecurityUser.fromEntity
    // already applied the configured policy, so a non-null value here means rotation is enforced.
    if (principal.credentialsExpireAt() != null) {
      extraClaims.put(JwtClaimNames.CREDENTIALS_EXPIRE_AT, principal.credentialsExpireAt().toEpochMilli());
    }

    return jwtService.generateToken(extraClaims, principal);
  }
}
