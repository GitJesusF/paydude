package com.jesusf.paydude.service;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.support.SecurityPropertiesFixture;
import com.jesusf.paydude.dto.auth.AuthResponse;
import com.jesusf.paydude.dto.auth.LoginRequest;
import com.jesusf.paydude.dto.auth.LoginResult;
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
import com.jesusf.paydude.security.JwtService;
import com.jesusf.paydude.security.SecurityUser;
import com.jesusf.paydude.service.MfaService.MfaVerification;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AuthServiceImpl}.
 *
 * <p>The auth service has three flows and a single non-obvious invariant. The flows — each in its
 * own {@code @Nested} class — are register (persist a user, publish a domain event, mint a JWT),
 * login (delegate credential verification to the {@link AuthenticationManager}, then either mint
 * tokens or issue an MFA challenge), and verifyMfa (redeem challenge + code for the token pair).
 * The invariant — pinned by the login tests — is that login does not perform a second DB read:
 * {@code DaoAuthenticationProvider} already loaded the user via {@code CustomUserDetailsService}
 * to verify the password, so the resulting {@code SecurityUser} principal is reused as the
 * source of claims. Reintroducing a {@code findByEmail} after {@code authenticate} would be a
 * regression.
 *
 * <p>Default-account creation is event-driven ({@code AccountEventListener}, tested separately),
 * so no account repository appears here — the {@link ApplicationEventPublisher} is the collaborator
 * that matters on register.
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

  private static final long EXPECTED_EXPIRES_IN_SECONDS = 86400L;

  @Mock
  private UserRepository userRepository;
  @Mock
  private PasswordEncoder passwordEncoder;
  @Mock
  private JwtService jwtService;
  @Mock
  private AuthenticationManager authenticationManager;
  @Mock
  private ApplicationEventPublisher eventPublisher;
  @Mock
  private BusinessMetrics metrics;
  @Mock
  private RefreshTokenService refreshTokenService;
  @Mock
  private BreachedPasswordGuard breachedPasswordGuard;
  // Wiring only — the SQL threshold logic behind the lockout is covered by AccountLockoutIT.
  @Mock
  private LoginAttemptService loginAttemptService;
  @Mock
  private SecurityAuditService securityAuditService;
  // Orchestration only — the RFC 6238 crypto is covered by TotpServiceTest.
  @Mock
  private MfaService mfaService;

  private static final String CLIENT_IP = "203.0.113.42";
  private static final String USER_AGENT = "test-suite/1.0";
  private static final String CANONICAL_EMAIL = "jesus@test.com";

  private AuthServiceImpl authService;

  @BeforeEach
  void setUp() {
    SecurityProperties properties = SecurityPropertiesFixture.defaults();
    authService = new AuthServiceImpl(
        userRepository,
        passwordEncoder,
        jwtService,
        authenticationManager,
        eventPublisher,
        properties,
        metrics,
        refreshTokenService,
        breachedPasswordGuard,
        loginAttemptService,
        securityAuditService,
        mfaService
    );
  }

  @Nested
  @DisplayName("Register flow — persist user, publish event, mint token")
  class RegisterFlow {

    @Test
    @DisplayName("Should register user, publish event and return OAuth-style token response")
    void shouldRegisterUserSuccessfully() {
      RegisterRequest request = new RegisterRequest(
          "Jesus", "Dev", "  Jesus@Test.COM  ", "password123"
      );

      when(userRepository.existsByEmail(CANONICAL_EMAIL)).thenReturn(false);
      when(passwordEncoder.encode(request.password())).thenReturn("encodedPass");

      User savedUser = User.builder()
          .id(1L)
          .email(CANONICAL_EMAIL)
          .firstName(request.firstName())
          .lastName(request.lastName())
          .role(Role.ROLE_USER)
          .password("encodedPass")
          .build();
      when(userRepository.save(any(User.class))).thenReturn(savedUser);

      String expectedToken = "jwt-token-xyz";
      when(jwtService.generateToken(any(), any())).thenReturn(expectedToken);
      when(jwtService.getExpirationSeconds()).thenReturn(EXPECTED_EXPIRES_IN_SECONDS);
      when(refreshTokenService.issueNewFamily(eq(1L), eq(CLIENT_IP), eq(USER_AGENT)))
          .thenReturn(new RefreshTokenService.IssuedRefreshToken("raw-refresh-token", Instant.now().plusSeconds(604800)));

      AuthResponse response = authService.register(request, CLIENT_IP, USER_AGENT);

      assertNotNull(response);
      assertEquals(expectedToken, response.accessToken());
      assertEquals("Bearer", response.tokenType());
      assertEquals(EXPECTED_EXPIRES_IN_SECONDS, response.expiresIn());

      ArgumentCaptor<User> savedUserCaptor = ArgumentCaptor.forClass(User.class);
      verify(userRepository).save(savedUserCaptor.capture());
      assertEquals(CANONICAL_EMAIL, savedUserCaptor.getValue().getEmail(),
          "registration must persist the canonical lower-case email");
      // Without this event the default account is never created; the listener's BEFORE_COMMIT
      // phase ties both writes to the same transaction.
      verify(eventPublisher).publishEvent(any(UserRegisteredEvent.class));
      verify(metrics).recordRegister();
      verify(securityAuditService).record(
          SecurityAuditEventType.REGISTER, SecurityAuditOutcome.SUCCESS, 1L, CANONICAL_EMAIL, null);
    }

    @Test
    @DisplayName("Should throw BusinessException when email already exists during register")
    void shouldThrowExceptionWhenEmailExists() {
      RegisterRequest request = new RegisterRequest(
          "Jesus", "Dev", "existing@test.com", "pass"
      );

      when(userRepository.existsByEmail(request.email())).thenReturn(true);

      assertThrows(BusinessException.class, () -> authService.register(request, CLIENT_IP, USER_AGENT));

      // No partial side effects: a published event would make the listener create a default
      // account for a user that was never saved.
      verify(userRepository, never()).save(any());
      verify(eventPublisher, never()).publishEvent(any());
    }

    @Test
    @DisplayName("Should reject registration when the chosen password is in a known breach corpus")
    void shouldRejectRegistrationWhenPasswordIsBreached() {
      RegisterRequest request = new RegisterRequest(
          "Jesus", "Dev", "jesus@test.com", "password123"
      );

      // The breach check runs after existsByEmail, so that stub is consumed too.
      when(userRepository.existsByEmail(request.email())).thenReturn(false);
      doThrow(new BusinessException("This password has appeared in a known data breach. Please choose a different one."))
          .when(breachedPasswordGuard).assertNotBreached(request.password());

      assertThrows(BusinessException.class, () -> authService.register(request, CLIENT_IP, USER_AGENT));

      verify(userRepository, never()).save(any());
      verify(eventPublisher, never()).publishEvent(any());
    }
  }

  @Nested
  @DisplayName("Login flow — single-read invariant and bad credentials handling")
  class LoginFlow {

    @Test
    @DisplayName("Should login by reading the principal cached in the Authentication, with no extra DB hit")
    void shouldLoginSuccessfully() {
      LoginRequest request = new LoginRequest("  Jesus@Test.COM  ", "password123");

      // What DaoAuthenticationProvider exposes after verifying the password (built by
      // CustomUserDetailsService in production).
      SecurityUser principal = new SecurityUser(
          1L,
          CANONICAL_EMAIL,
          "encodedPass",
          UserStatus.ACTIVE,
          null,
          null,
          false,  // single-factor account: login must complete with tokens, not a challenge
          List.of(new SimpleGrantedAuthority(Role.ROLE_USER.name()))
      );

      Authentication auth = mock(Authentication.class);
      when(auth.getPrincipal()).thenReturn(principal);
      when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
          .thenReturn(auth);

      when(jwtService.generateToken(any(), any())).thenReturn("login-token-123");
      when(jwtService.getExpirationSeconds()).thenReturn(EXPECTED_EXPIRES_IN_SECONDS);
      when(refreshTokenService.issueNewFamily(eq(1L), eq(CLIENT_IP), eq(USER_AGENT)))
          .thenReturn(new RefreshTokenService.IssuedRefreshToken("login-refresh", Instant.now().plusSeconds(604800)));

      LoginResult result = authService.login(request, CLIENT_IP, USER_AGENT);

      AuthResponse response = assertInstanceOf(LoginResult.Tokens.class, result,
          "single-factor login must produce LoginResult.Tokens").tokens();

      assertNotNull(response);
      assertEquals("login-token-123", response.accessToken());
      assertEquals("Bearer", response.tokenType());
      assertEquals(EXPECTED_EXPIRES_IN_SECONDS, response.expiresIn());

      verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
      ArgumentCaptor<UsernamePasswordAuthenticationToken> authRequestCaptor =
          ArgumentCaptor.forClass(UsernamePasswordAuthenticationToken.class);
      verify(authenticationManager).authenticate(authRequestCaptor.capture());
      assertEquals(CANONICAL_EMAIL, authRequestCaptor.getValue().getName(),
          "login must authenticate using the canonical lower-case email");
      verify(securityAuditService).record(
          SecurityAuditEventType.LOGIN, SecurityAuditOutcome.SUCCESS, 1L, CANONICAL_EMAIL, null);
      // The single-read invariant: everything the claims need already lives in the principal.
      // Reintroducing a findByEmail after authenticate() would be a regression.
      verifyNoInteractions(userRepository);
    }

    @Test
    @DisplayName("Should throw exception when login fails (Bad Credentials)")
    void shouldThrowExceptionOnBadCredentials() {
      LoginRequest request = new LoginRequest("wrong@test.com", "wrongPass");

      doThrow(new BadCredentialsException("Bad creds"))
          .when(authenticationManager).authenticate(any());

      assertThrows(BadCredentialsException.class, () -> authService.login(request, CLIENT_IP, USER_AGENT));

      verify(jwtService, never()).generateToken(any(), any());
      verifyNoInteractions(userRepository);
      verify(securityAuditService).record(
          SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE, null, "wrong@test.com", "bad credentials");
    }

    @Test
    @DisplayName("Should release an expired lock before authenticating and reset the counter on success")
    void shouldDriveLockoutOnSuccessfulLogin() {
      LoginRequest request = new LoginRequest("  Jesus@Test.COM  ", "password123");

      SecurityUser principal = new SecurityUser(
          1L, CANONICAL_EMAIL, "encodedPass", UserStatus.ACTIVE, null, null, false,
          List.of(new SimpleGrantedAuthority(Role.ROLE_USER.name()))
      );
      Authentication auth = mock(Authentication.class);
      when(auth.getPrincipal()).thenReturn(principal);
      when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
          .thenReturn(auth);
      when(jwtService.generateToken(any(), any())).thenReturn("login-token");
      when(jwtService.getExpirationSeconds()).thenReturn(EXPECTED_EXPIRES_IN_SECONDS);
      when(refreshTokenService.issueNewFamily(eq(1L), eq(CLIENT_IP), eq(USER_AGENT)))
          .thenReturn(new RefreshTokenService.IssuedRefreshToken("login-refresh", Instant.now().plusSeconds(604800)));

      authService.login(request, CLIENT_IP, USER_AGENT);

      // The expired-lock release must precede authenticate(), so a correct password on a lapsed
      // lock window logs in within the same request.
      InOrder inOrder = inOrder(loginAttemptService, authenticationManager);
      inOrder.verify(loginAttemptService).releaseExpiredLock(CANONICAL_EMAIL);
      inOrder.verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
      verify(loginAttemptService).recordSuccess(1L);
      verify(loginAttemptService, never()).recordFailure(any());
    }

    @Test
    @DisplayName("Should count a failed attempt (feeding lockout) on bad credentials, without resetting")
    void shouldDriveLockoutOnBadCredentials() {
      LoginRequest request = new LoginRequest("  Jesus@Test.COM  ", "wrongPass");

      doThrow(new BadCredentialsException("Bad creds"))
          .when(authenticationManager).authenticate(any());

      assertThrows(BadCredentialsException.class, () -> authService.login(request, CLIENT_IP, USER_AGENT));

      verify(loginAttemptService).releaseExpiredLock(CANONICAL_EMAIL);
      verify(loginAttemptService).recordFailure(CANONICAL_EMAIL);
      verify(loginAttemptService, never()).recordSuccess(any());
      verify(metrics).recordLogin(false);
    }

    @Test
    @DisplayName("Should return an MFA challenge — not tokens — when the account is enrolled, "
        + "without resetting the lockout counter")
    void shouldReturnMfaChallengeWhenEnrolled() {
      LoginRequest request = new LoginRequest(CANONICAL_EMAIL, "password123");

      // mfaEnabled=true: the password checked out, but the account demands a second factor.
      SecurityUser principal = new SecurityUser(
          1L, CANONICAL_EMAIL, "encodedPass", UserStatus.ACTIVE, null, null, true,
          List.of(new SimpleGrantedAuthority(Role.ROLE_USER.name()))
      );
      Authentication auth = mock(Authentication.class);
      when(auth.getPrincipal()).thenReturn(principal);
      when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
          .thenReturn(auth);
      when(jwtService.generateMfaChallengeToken(1L)).thenReturn("challenge-token");
      when(jwtService.getMfaChallengeExpirationSeconds()).thenReturn(300L);

      LoginResult result = authService.login(request, CLIENT_IP, USER_AGENT);

      var challenge = assertInstanceOf(LoginResult.MfaRequired.class, result,
          "an MFA-enrolled account must receive a challenge, never tokens").challenge();
      assertTrue(challenge.mfaRequired());
      assertEquals("challenge-token", challenge.mfaToken());
      assertEquals(300L, challenge.expiresIn());

      // Step-up invariants: the login is not complete — no refresh family, no login-success
      // metric, and crucially no counter reset. Resetting here would hand an attacker holding
      // the password max-attempts fresh TOTP guesses per challenge cycle.
      verifyNoInteractions(refreshTokenService);
      verify(loginAttemptService, never()).recordSuccess(any());
      verify(metrics, never()).recordLogin(anyBoolean());
      // The challenge does land in the audit trail: one with no later LOGIN/SUCCESS is the
      // forensic marker of a compromised password stopped by the second factor.
      verify(securityAuditService).record(
          SecurityAuditEventType.MFA_CHALLENGE, SecurityAuditOutcome.SUCCESS,
          1L, CANONICAL_EMAIL, "password verified; second factor pending");
    }
  }

  @Nested
  @DisplayName("VerifyMfa flow — challenge redemption, lockout feeding, token minting")
  class VerifyMfaFlow {

    private static final String CHALLENGE_TOKEN = "challenge-token";

    private User enrolledUser() {
      return User.builder()
          .id(1L)
          .email(CANONICAL_EMAIL)
          .firstName("Jesus")
          .lastName("Dev")
          .password("encodedPass")
          .role(Role.ROLE_USER)
          .status(UserStatus.ACTIVE)
          .passwordChangedAt(Instant.now())
          .mfaEnabled(true)
          .mfaSecret("JBSWY3DPEHPK3PXP")
          .build();
    }

    private Claims stubChallengeParse() {
      // The Claims content is irrelevant — extractUserId is stubbed separately; only the typed
      // parse acceptance matters.
      Claims claims = mock(Claims.class);
      when(jwtService.parseMfaChallengeClaims(CHALLENGE_TOKEN)).thenReturn(claims);
      when(jwtService.extractUserId(claims)).thenReturn(1L);
      return claims;
    }

    @Test
    @DisplayName("Should mint the token pair when the TOTP code verifies, resetting the counter")
    void shouldMintTokensOnValidTotp() {
      stubChallengeParse();
      User user = enrolledUser();
      when(userRepository.findById(1L)).thenReturn(Optional.of(user));
      when(mfaService.verify(user, "123456")).thenReturn(MfaVerification.TOTP);
      when(jwtService.generateToken(any(), any())).thenReturn("mfa-access-token");
      when(jwtService.getExpirationSeconds()).thenReturn(EXPECTED_EXPIRES_IN_SECONDS);
      when(refreshTokenService.issueNewFamily(eq(1L), eq(CLIENT_IP), eq(USER_AGENT)))
          .thenReturn(new RefreshTokenService.IssuedRefreshToken("mfa-refresh", Instant.now().plusSeconds(604800)));

      AuthResponse response = authService.verifyMfa(
          new MfaVerifyRequest(CHALLENGE_TOKEN, "123456"), CLIENT_IP, USER_AGENT);

      assertEquals("mfa-access-token", response.accessToken());
      assertEquals("mfa-refresh", response.refreshToken());
      // Only with both factors proven is the login complete: counter reset, login metric, and
      // the factor named in the audit detail.
      verify(loginAttemptService).recordSuccess(1L);
      verify(metrics).recordMfaVerification(true);
      verify(metrics).recordLogin(true);
      verify(securityAuditService).record(
          SecurityAuditEventType.LOGIN, SecurityAuditOutcome.SUCCESS, 1L, CANONICAL_EMAIL, "mfa: totp");
    }

    @Test
    @DisplayName("Should audit the recovery-code path distinctly")
    void shouldAuditRecoveryCodeRedemption() {
      stubChallengeParse();
      User user = enrolledUser();
      when(userRepository.findById(1L)).thenReturn(Optional.of(user));
      when(mfaService.verify(user, "K7QW-2MNB-X4ZC")).thenReturn(MfaVerification.RECOVERY_CODE);
      when(jwtService.generateToken(any(), any())).thenReturn("mfa-access-token");
      when(jwtService.getExpirationSeconds()).thenReturn(EXPECTED_EXPIRES_IN_SECONDS);
      when(refreshTokenService.issueNewFamily(eq(1L), eq(CLIENT_IP), eq(USER_AGENT)))
          .thenReturn(new RefreshTokenService.IssuedRefreshToken("mfa-refresh", Instant.now().plusSeconds(604800)));

      authService.verifyMfa(new MfaVerifyRequest(CHALLENGE_TOKEN, "K7QW-2MNB-X4ZC"), CLIENT_IP, USER_AGENT);

      // A redeemed recovery code is a distinct forensic signal from a routine TOTP (lost
      // device — or an attacker who found the printed codes); the detail tells them apart.
      verify(securityAuditService).record(
          SecurityAuditEventType.LOGIN, SecurityAuditOutcome.SUCCESS, 1L, CANONICAL_EMAIL,
          "mfa: recovery code");
    }

    @Test
    @DisplayName("Should feed the persistent lockout and return 401 on a wrong code")
    void shouldFeedLockoutOnInvalidCode() {
      stubChallengeParse();
      User user = enrolledUser();
      when(userRepository.findById(1L)).thenReturn(Optional.of(user));
      when(mfaService.verify(user, "000000")).thenReturn(MfaVerification.INVALID);

      assertThrows(BadCredentialsException.class,
          () -> authService.verifyMfa(new MfaVerifyRequest(CHALLENGE_TOKEN, "000000"), CLIENT_IP, USER_AGENT));

      // A wrong code is a failed login in its own right: it feeds the persistent lockout
      // (REQUIRES_NEW survives this rollback), gets measured and audited. No session, no reset.
      verify(loginAttemptService).recordFailure(CANONICAL_EMAIL);
      verify(loginAttemptService, never()).recordSuccess(any());
      verify(metrics).recordMfaVerification(false);
      verify(securityAuditService).record(
          SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE, 1L, CANONICAL_EMAIL,
          "invalid mfa code");
      verifyNoInteractions(refreshTokenService);
    }

    @Test
    @DisplayName("Should collapse an invalid/expired challenge token into the same generic 401")
    void shouldRejectInvalidChallengeToken() {
      when(jwtService.parseMfaChallengeClaims("garbage"))
          .thenThrow(new JwtException("signature mismatch"));

      assertThrows(BadCredentialsException.class,
          () -> authService.verifyMfa(new MfaVerifyRequest("garbage", "123456"), CLIENT_IP, USER_AGENT));

      // No proven identity → neither the DB nor the code verifier is touched; the failure is
      // audited without a principal (a volumetric signal) and measured.
      verifyNoInteractions(userRepository, mfaService, refreshTokenService);
      verify(metrics).recordMfaVerification(false);
      verify(securityAuditService).record(
          SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE, null, null,
          "invalid mfa challenge token");
    }

    @Test
    @DisplayName("Should surface 423 when the account got locked between challenge and verify")
    void shouldRejectLockedAccount() {
      stubChallengeParse();
      User user = enrolledUser();
      user.setStatus(UserStatus.LOCKED);
      user.setLockoutExpiresAt(Instant.now().plusSeconds(600));
      when(userRepository.findById(1L)).thenReturn(Optional.of(user));
      // The lock window has not lapsed: releaseExpiredLock frees nothing.
      when(loginAttemptService.releaseExpiredLock(CANONICAL_EMAIL)).thenReturn(false);

      assertThrows(LockedException.class,
          () -> authService.verifyMfa(new MfaVerifyRequest(CHALLENGE_TOKEN, "123456"), CLIENT_IP, USER_AGENT));

      // A locked account never gets to burn code attempts or mint a session, but the rejection
      // is not invisible: same metric and audit row as any other failed MFA verification.
      verifyNoInteractions(mfaService, refreshTokenService);
      verify(metrics).recordMfaVerification(false);
      verify(securityAuditService).record(
          SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE, 1L, CANONICAL_EMAIL,
          "LockedException");
    }

    @Test
    @DisplayName("Should surface 403 — with metric and audit row — when the account was suspended mid-challenge")
    void shouldRejectDisabledAccount() {
      stubChallengeParse();
      User user = enrolledUser();
      user.setStatus(UserStatus.SUSPENDED);
      when(userRepository.findById(1L)).thenReturn(Optional.of(user));

      assertThrows(DisabledException.class,
          () -> authService.verifyMfa(new MfaVerifyRequest(CHALLENGE_TOKEN, "123456"), CLIENT_IP, USER_AGENT));

      verifyNoInteractions(mfaService, refreshTokenService);
      verify(metrics).recordMfaVerification(false);
      verify(securityAuditService).record(
          SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE, 1L, CANONICAL_EMAIL,
          "DisabledException");
    }

    @Test
    @DisplayName("Should collapse a challenge for a since-deleted user into the generic 401, audited")
    void shouldRejectChallengeForUnknownUser() {
      stubChallengeParse();
      when(userRepository.findById(1L)).thenReturn(Optional.empty());

      assertThrows(BadCredentialsException.class,
          () -> authService.verifyMfa(new MfaVerifyRequest(CHALLENGE_TOKEN, "123456"), CLIENT_IP, USER_AGENT));

      // The signed userId is kept in the audit row (that identity did exist); no email is known.
      verifyNoInteractions(mfaService, refreshTokenService);
      verify(metrics).recordMfaVerification(false);
      verify(securityAuditService).record(
          SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE, 1L, null,
          "mfa challenge for unknown user");
    }

    @Test
    @DisplayName("Should reject — with metric and audit row — when MFA was disabled between challenge and verify")
    void shouldRejectWhenMfaNoLongerEnabled() {
      stubChallengeParse();
      User user = enrolledUser();
      user.setMfaEnabled(false);
      when(userRepository.findById(1L)).thenReturn(Optional.of(user));

      assertThrows(BadCredentialsException.class,
          () -> authService.verifyMfa(new MfaVerifyRequest(CHALLENGE_TOKEN, "123456"), CLIENT_IP, USER_AGENT));

      verifyNoInteractions(mfaService, refreshTokenService);
      verify(metrics).recordMfaVerification(false);
      verify(securityAuditService).record(
          SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE, 1L, CANONICAL_EMAIL,
          "mfa no longer enabled at verify");
    }
  }
}
