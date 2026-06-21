package com.jesusf.paydude.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.dto.auth.LoginRequest;
import com.jesusf.paydude.dto.auth.MfaVerifyRequest;
import com.jesusf.paydude.dto.auth.RegisterRequest;
import com.jesusf.paydude.dto.user.MfaConfirmRequest;
import com.jesusf.paydude.dto.user.MfaDisableRequest;
import com.jesusf.paydude.dto.user.MfaSetupRequest;
import com.jesusf.paydude.entity.SecurityAuditEvent;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.repository.MfaRecoveryCodeRepository;
import com.jesusf.paydude.repository.SecurityAuditEventRepository;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.security.TotpService;
import com.jesusf.paydude.support.TestcontainersConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end integration coverage for the TOTP second factor (pattern #24), over the real HTTP
 * surface: real security filter chain (the {@code typ} separation between access and challenge
 * tokens is exercised for real), real Flyway schema (V0_004), real Postgres for the two atomic
 * single-use guards (TOTP step, recovery code), and the real {@link TotpService} computing codes
 * on both sides — the test plays the authenticator app.
 *
 * <p>Clock strategy: no sleeping and no clock mocking. Enrollment confirms with the code for the
 * <i>current</i> step (consuming it as the replay baseline); the login step-up then verifies with
 * the code for {@code currentStep + 1}, which the ±1-step window accepts and which is strictly
 * newer than the baseline. Both remain valid across a step boundary mid-test, so the tests are
 * deterministic on any machine.
 *
 * <p>Each test enrolls its own user from its own client IP ({@code 203.0.113.x}): the register
 * and MFA per-IP buckets are real here, and unique IPs keep tests order-independent.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class MfaLoginIT {

  private static final String PASSWORD = "correct-horse-battery";
  private static final String WRONG_CODE = "000000";
  private static final String USER_AGENT = "PayDudeMfaLoginIT/1.0";

  // One unique IP per enrolled user — the register-by-ip bucket (5/h) is real in this IT.
  private static final AtomicInteger LAST_IP_OCTET = new AtomicInteger(1);

  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper objectMapper;
  @Autowired private TotpService totpService;
  @Autowired private UserRepository userRepository;
  @Autowired private MfaRecoveryCodeRepository recoveryCodeRepository;
  @Autowired private SecurityAuditEventRepository auditRepository;
  @Autowired private SecurityProperties securityProperties;

  /** Everything later steps need about an enrolled user. */
  private record Enrolled(String email, String ip, String registrationAccessToken,
                          String secret, List<String> recoveryCodes) {}

  @Test
  @DisplayName("Full journey: setup/confirm arm TOTP, login yields a challenge, the code buys a "
      + "working session, and the audit trail records both halves")
  void shouldCompleteFullTotpJourney() throws Exception {
    Enrolled user = enroll();

    // With MFA armed, the correct password no longer returns tokens: 200 with the challenge
    // shape (mfaRequired discriminates) and — critically — no trace of access/refresh tokens.
    String mfaToken = objectMapper.readTree(
            postJson("/v1/auth/login", new LoginRequest(user.email(), PASSWORD), user.ip(), null)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mfaRequired").value(true))
                .andExpect(jsonPath("$.expiresIn").value(300))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andReturn().getResponse().getContentAsString())
        .get("mfaToken").asText();

    // The "authenticator" computes the next step's code (inside the ±1 window, strictly newer
    // than the baseline seeded at confirm) and redeems the challenge for the token pair.
    String code = totpService.codeAt(user.secret(), totpService.currentTimeStep() + 1);
    JsonNode tokens = objectMapper.readTree(
        postJson("/v1/auth/mfa/verify", new MfaVerifyRequest(mfaToken, code), user.ip(), null)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").exists())
            .andExpect(jsonPath("$.refreshToken").exists())
            .andReturn().getResponse().getContentAsString());

    // The minted session is a first-class access token: it passes JwtAuthenticationFilter
    // (typ=at+jwt) and authorizes reading the caller's own profile.
    mockMvc.perform(get("/v1/users/me")
            .header("Authorization", "Bearer " + tokens.get("accessToken").asText()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.email").value(user.email()));

    // Persisted state: enrolled, with the replay baseline advanced by the verify.
    User row = userRepository.findByEmail(user.email()).orElseThrow();
    assertTrue(row.isMfaEnabled());
    assertNotNull(row.getMfaLastUsedStep(), "the verified step must be persisted as replay baseline");

    // Detection leg: the challenge and the completed login land in the audit trail, the detail
    // naming the factor used.
    assertEquals(1, auditEvents(user.email(), SecurityAuditEventType.MFA_CHALLENGE, SecurityAuditOutcome.SUCCESS).size());
    List<SecurityAuditEvent> logins = auditEvents(user.email(), SecurityAuditEventType.LOGIN, SecurityAuditOutcome.SUCCESS);
    assertEquals(1, logins.size());
    assertEquals("mfa: totp", logins.get(0).getDetail());
  }

  @Test
  @DisplayName("A TOTP code is single-use: replaying it on a fresh challenge yields 401 and feeds "
      + "the lockout counter")
  void shouldRejectReplayedTotpCode() throws Exception {
    Enrolled user = enroll();

    String code = totpService.codeAt(user.secret(), totpService.currentTimeStep() + 1);
    postJson("/v1/auth/mfa/verify", new MfaVerifyRequest(loginForChallenge(user), code), user.ip(), null)
        .andExpect(status().isOk());

    // Same code, fresh challenge: cryptographically it may still be in the window, but its step
    // is consumed (RFC 6238 §5.2). The response is the same generic 401 as a wrong code.
    postJson("/v1/auth/mfa/verify", new MfaVerifyRequest(loginForChallenge(user), code), user.ip(), null)
        .andExpect(status().isUnauthorized());

    // And the attempt fed the persistent counter — a replay is a failed login in its own right.
    assertEquals(1, userRepository.findByEmail(user.email()).orElseThrow().getFailedLoginAttempts());
  }

  @Test
  @DisplayName("A recovery code redeems exactly once; the next one still works")
  void shouldRedeemRecoveryCodeExactlyOnce() throws Exception {
    Enrolled user = enroll();
    String firstCode = user.recoveryCodes().get(0);

    postJson("/v1/auth/mfa/verify", new MfaVerifyRequest(loginForChallenge(user), firstCode), user.ip(), null)
        .andExpect(status().isOk());

    // The consume is an atomic UPDATE guarded by used_at IS NULL: a second redemption of the
    // same code matches no row → 401.
    postJson("/v1/auth/mfa/verify", new MfaVerifyRequest(loginForChallenge(user), firstCode), user.ip(), null)
        .andExpect(status().isUnauthorized());

    // The rest of the batch stays valid — burning one code does not invalidate the others.
    postJson("/v1/auth/mfa/verify",
        new MfaVerifyRequest(loginForChallenge(user), user.recoveryCodes().get(1)), user.ip(), null)
        .andExpect(status().isOk());

    // The forensic detail tells the factors apart: two LOGIN/SUCCESS via recovery code.
    List<SecurityAuditEvent> logins = auditEvents(user.email(), SecurityAuditEventType.LOGIN, SecurityAuditOutcome.SUCCESS);
    assertEquals(2, logins.stream().filter(e -> "mfa: recovery code".equals(e.getDetail())).count());
  }

  @Test
  @DisplayName("The challenge token is not a Bearer credential: typ=mfa+jwt dies at the filter")
  void shouldRejectChallengeTokenAsBearer() throws Exception {
    Enrolled user = enroll();
    String mfaToken = loginForChallenge(user);

    // Half an authentication (password only) buys no API access: the filter demands typ=at+jwt
    // and answers with the canonical 401 + RFC 6750 challenge.
    mockMvc.perform(get("/v1/users/me")
            .header("Authorization", "Bearer " + mfaToken))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.status").value(401));
  }

  @Test
  @DisplayName("Disable (password-gated) removes the second factor: login returns plain tokens again")
  void shouldDisableMfaAndRestoreSingleFactorLogin() throws Exception {
    Enrolled user = enroll();

    postJson("/v1/users/me/mfa/disable", new MfaDisableRequest(PASSWORD),
        user.ip(), user.registrationAccessToken())
        .andExpect(status().isNoContent());

    // Without a second factor, the same login endpoint goes back to the plain token shape.
    postJson("/v1/auth/login", new LoginRequest(user.email(), PASSWORD), user.ip(), null)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accessToken").exists())
        .andExpect(jsonPath("$.mfaRequired").doesNotExist());

    // Full cleanup: no secret, no baseline, no orphaned recovery codes.
    User row = userRepository.findByEmail(user.email()).orElseThrow();
    assertNull(row.getMfaSecret());
    assertNull(row.getMfaLastUsedStep());
    long remainingCodes = StreamSupport.stream(recoveryCodeRepository.findAll().spliterator(), false)
        .filter(codeRow -> codeRow.getUserId().equals(row.getId()))
        .count();
    assertEquals(0, remainingCodes, "disable must delete every recovery code");
  }

  @Test
  @DisplayName("Repeated wrong codes lock the account (423), exactly like wrong passwords")
  void shouldLockAccountAfterRepeatedWrongCodes() throws Exception {
    Enrolled user = enroll();
    String mfaToken = loginForChallenge(user);

    int maxAttempts = securityProperties.lockout().maxAttempts();
    for (int i = 0; i < maxAttempts; i++) {
      postJson("/v1/auth/mfa/verify", new MfaVerifyRequest(mfaToken, wrongCodeFor(user.secret())),
          user.ip(), null)
          .andExpect(status().isUnauthorized());
    }

    // The threshold fired LoginAttemptService's atomic UPDATE (REQUIRES_NEW, surviving the 401
    // rollbacks): the account is LOCKED in the database…
    assertEquals(UserStatus.LOCKED, userRepository.findByEmail(user.email()).orElseThrow().getStatus());

    // …and not even the CORRECT code gets in any more: verify re-reads account state from the DB
    // and answers the same 423 as a password-locked login.
    String correctCode = totpService.codeAt(user.secret(), totpService.currentTimeStep() + 1);
    postJson("/v1/auth/mfa/verify", new MfaVerifyRequest(mfaToken, correctCode), user.ip(), null)
        .andExpect(status().isLocked());
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  /** Registers a fresh user over HTTP and completes the full TOTP enrollment (setup + confirm). */
  private Enrolled enroll() throws Exception {
    String email = "mfa-" + UUID.randomUUID() + "@test.com";
    String ip = "203.0.113." + LAST_IP_OCTET.getAndIncrement();

    String accessToken = objectMapper.readTree(
            postJson("/v1/auth/register", new RegisterRequest("Mfa", "User", email, PASSWORD), ip, null)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString())
        .get("accessToken").asText();

    String secret = objectMapper.readTree(
            postJson("/v1/users/me/mfa/setup", new MfaSetupRequest(PASSWORD), ip, accessToken)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.otpauthUri").exists())
                .andReturn().getResponse().getContentAsString())
        .get("secret").asText();

    // The test plays the authenticator: it confirms with the CURRENT step's code, which is
    // consumed as the replay-guard baseline (hence later verifies use step + 1).
    String confirmCode = totpService.codeAt(secret, totpService.currentTimeStep());
    JsonNode confirm = objectMapper.readTree(
        postJson("/v1/users/me/mfa/confirm", new MfaConfirmRequest(confirmCode), ip, accessToken)
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString());
    List<String> recoveryCodes = StreamSupport.stream(confirm.get("recoveryCodes").spliterator(), false)
        .map(JsonNode::asText)
        .toList();
    assertEquals(10, recoveryCodes.size(), "confirm must hand out the full recovery batch");

    return new Enrolled(email, ip, accessToken, secret, recoveryCodes);
  }

  /** Runs the password stage and returns the fresh challenge token. */
  private String loginForChallenge(Enrolled user) throws Exception {
    return objectMapper.readTree(
            postJson("/v1/auth/login", new LoginRequest(user.email(), PASSWORD), user.ip(), null)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mfaRequired").value(true))
                .andReturn().getResponse().getContentAsString())
        .get("mfaToken").asText();
  }

  /**
   * A deterministic wrong code: {@code 000000} unless it accidentally collides with one of the
   * three codes the ±1 window would accept right now (probability ~3·10⁻⁶ — handled anyway so
   * the suite can never flake on a jackpot).
   */
  private String wrongCodeFor(String secret) {
    long step = totpService.currentTimeStep();
    for (long s = step - 1; s <= step + 1; s++) {
      if (totpService.codeAt(secret, s).equals(WRONG_CODE)) {
        return "999999";
      }
    }
    return WRONG_CODE;
  }

  private ResultActions postJson(String path, Object body, String ip, String bearerToken) throws Exception {
    MockHttpServletRequestBuilder request = post(path)
        .contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(body))
        .header("User-Agent", USER_AGENT)
        .with(req -> {
          req.setRemoteAddr(ip);
          return req;
        });
    if (bearerToken != null) {
      request.header("Authorization", "Bearer " + bearerToken);
    }
    return mockMvc.perform(request);
  }

  private List<SecurityAuditEvent> auditEvents(String principal, SecurityAuditEventType type,
                                               SecurityAuditOutcome outcome) {
    return auditRepository
        .search(null, type, outcome, PageRequest.of(0, 1000, Sort.by(Sort.Direction.DESC, "createdAt")))
        .getContent().stream()
        .filter(e -> principal.equals(e.getPrincipal()))
        .toList();
  }
}
