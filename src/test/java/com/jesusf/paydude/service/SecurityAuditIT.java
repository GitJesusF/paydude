package com.jesusf.paydude.service;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.dto.auth.AuthResponse;
import com.jesusf.paydude.dto.auth.LoginRequest;
import com.jesusf.paydude.dto.auth.LoginResult;
import com.jesusf.paydude.dto.auth.RegisterRequest;
import com.jesusf.paydude.entity.SecurityAuditEvent;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.Role;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.repository.SecurityAuditEventRepository;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.service.RefreshTokenService.IssuedRefreshToken;
import com.jesusf.paydude.support.TestcontainersConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration coverage for the security audit log.
 *
 * <p>The unit tests pin the in-process behaviour, but only a real Spring transaction against Postgres
 * can prove the two properties that matter most:
 *
 * <ol>
 *   <li><b>Durability.</b> A failed login (and the lockout it triggers, and a refresh-token reuse)
 *       rolls its business transaction back — yet the audit row, written in a {@code REQUIRES_NEW}
 *       transaction, must survive. This is the same property {@code AccountLockoutIT} proves for the
 *       failure counter and {@code RefreshTokenReuseDetectionIT} proves for family revocation.</li>
 *   <li><b>RBAC.</b> The read endpoint {@code GET /v1/admin/audit-events} is reachable by a
 *       {@code ROLE_ADMIN} bearer token (200) and forbidden to a normal user (403) — exercised over
 *       the real security filter chain.</li>
 * </ol>
 *
 * <p>The durability cases drive {@code AuthService} / {@code RefreshTokenService} directly rather than
 * the HTTP endpoints: the controller consumes {@code AuthRateLimiter}'s per-email bucket, which would
 * trip a {@code 429} around the same count the lockout trips — the same reasoning as
 * {@code AccountLockoutIT}. The RBAC case needs the real chain, so it goes through {@code MockMvc}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class SecurityAuditIT {

  private static final String CLIENT_IP = "203.0.113.42";
  private static final String USER_AGENT = "PayDudeSecurityAuditIT/1.0";
  private static final String PASSWORD = "correct-horse-battery";
  private static final String WRONG_PASSWORD = "wrong-password";

  @Autowired private AuthService authService;
  @Autowired private RefreshTokenService refreshTokenService;
  @Autowired private UserRepository userRepository;
  @Autowired private SecurityAuditEventRepository auditRepository;
  @Autowired private PasswordEncoder passwordEncoder;
  @Autowired private SecurityProperties securityProperties;
  @Autowired private MockMvc mockMvc;

  // ---------------------------------------------------------------------------------------------
  // Durability: the audit event survives the audited operation's rollback.
  // ---------------------------------------------------------------------------------------------

  @Test
  @DisplayName("A failed login is recorded (LOGIN/FAILURE) even though the login transaction rolls back")
  void failedLoginIsAuditedDespiteRollback() {
    String email = "audit-login-" + UUID.randomUUID() + "@test.com";
    authService.register(new RegisterRequest("Audit", "Login", email, PASSWORD), CLIENT_IP, USER_AGENT);

    assertThrows(BadCredentialsException.class,
        () -> authService.login(new LoginRequest(email, WRONG_PASSWORD), CLIENT_IP, USER_AGENT));

    // The login transaction rolls back with the BadCredentialsException, but the audit event was
    // written in its own REQUIRES_NEW transaction: it must still be present and queryable.
    SecurityAuditEvent row = singleEventFor(email, SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE);
    assertNull(row.getUserId(), "a failed login records no userId — only the attempted principal");
    assertEquals(email, row.getPrincipal());
    assertEquals("bad credentials", row.getDetail());
    assertNotNull(row.getCreatedAt(), "the @CreatedDate timestamp must be stamped on persist");
  }

  @Test
  @DisplayName("Crossing the lockout threshold records an ACCOUNT_LOCKED audit event")
  void lockoutIsAudited() {
    String email = "audit-lock-" + UUID.randomUUID() + "@test.com";
    authService.register(new RegisterRequest("Audit", "Lock", email, PASSWORD), CLIENT_IP, USER_AGENT);

    int maxAttempts = securityProperties.lockout().maxAttempts();
    for (int i = 0; i < maxAttempts; i++) {
      assertThrows(BadCredentialsException.class,
          () -> authService.login(new LoginRequest(email, WRONG_PASSWORD), CLIENT_IP, USER_AGENT));
    }

    // The LOCKED transition happens inside LoginAttemptService's atomic UPDATE (REQUIRES_NEW);
    // the ACCOUNT_LOCKED event is persisted there against the target email, with no userId.
    SecurityAuditEvent row =
        singleEventFor(email, SecurityAuditEventType.ACCOUNT_LOCKED, SecurityAuditOutcome.FAILURE);
    assertEquals(email, row.getPrincipal());
    assertNull(row.getUserId(), "lockout is keyed by email (atomic UPDATE), so no userId is recorded");
  }

  @Test
  @DisplayName("Refresh-token reuse detection records a TOKEN_REUSE_DETECTED audit event")
  void tokenReuseIsAudited() {
    User user = userRepository.save(User.builder()
        .firstName("Audit").lastName("Reuse")
        .email("audit-reuse-" + UUID.randomUUID() + "@test.com")
        .password(passwordEncoder.encode(PASSWORD))
        .role(Role.ROLE_USER).status(UserStatus.ACTIVE)
        .passwordChangedAt(Instant.now()).build());

    IssuedRefreshToken first = refreshTokenService.issueNewFamily(user.getId(), CLIENT_IP, USER_AGENT);
    refreshTokenService.rotate(first.rawToken(), CLIENT_IP, USER_AGENT);
    // Re-presenting the already-rotated original trips reuse detection (and revokes the family).
    // The event must survive the BadCredentialsException rotate() throws back to the client.
    assertThrows(BadCredentialsException.class,
        () -> refreshTokenService.rotate(first.rawToken(), CLIENT_IP, USER_AGENT));

    SecurityAuditEvent row = auditRepository.search(user.getId(),
            SecurityAuditEventType.TOKEN_REUSE_DETECTED, SecurityAuditOutcome.FAILURE,
            PageRequest.of(0, 10))
        .getContent().stream().findFirst()
        .orElseThrow(() -> new AssertionError("a TOKEN_REUSE_DETECTED row must exist for the user"));
    assertEquals(user.getId(), row.getUserId());
  }

  // ---------------------------------------------------------------------------------------------
  // RBAC: the read endpoint is admin-only.
  // ---------------------------------------------------------------------------------------------

  @Test
  @DisplayName("Admin reads the audit trail (200); a normal user's valid token is forbidden (403)")
  void adminReadsTrailUserForbidden() throws Exception {
    String userEmail = "audit-user-" + UUID.randomUUID() + "@test.com";
    AuthResponse userAuth = authService.register(
        new RegisterRequest("Plain", "User", userEmail, PASSWORD), CLIENT_IP, USER_AGENT);

    mockMvc.perform(get("/v1/admin/audit-events")
            .header("Authorization", "Bearer " + userAuth.accessToken()))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.status").value(403));

    // register only creates ROLE_USER, so seed a ROLE_ADMIN directly and get a real JWT via
    // authService.login (which bypasses the controller's AuthRateLimiter).
    String adminEmail = "audit-admin-" + UUID.randomUUID() + "@test.com";
    userRepository.save(User.builder()
        .firstName("Admin").lastName("User").email(adminEmail)
        .password(passwordEncoder.encode(PASSWORD))
        .role(Role.ROLE_ADMIN).status(UserStatus.ACTIVE)
        .passwordChangedAt(Instant.now()).build());
    // login returns the sealed LoginResult; the seeded admin has no MFA, so it is Tokens.
    AuthResponse adminAuth = ((LoginResult.Tokens) authService
        .login(new LoginRequest(adminEmail, PASSWORD), CLIENT_IP, USER_AGENT)).tokens();

    mockMvc.perform(get("/v1/admin/audit-events")
            .header("Authorization", "Bearer " + adminAuth.accessToken()))
        .andExpect(status().isOk())
        // PagedResponse envelope — the endpoint never exposes the raw PageImpl.
        .andExpect(jsonPath("$.content").exists())
        .andExpect(jsonPath("$.totalElements").exists())
        .andExpect(jsonPath("$.hasNext").exists());
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  /**
   * Finds the single audit row of {@code (type, outcome)} whose principal is this test's unique email.
   * Filtering by the per-test UUID email isolates the row from those left by other tests sharing the
   * Postgres container; the newest-first sort keeps this test's just-written row within the page.
   */
  private SecurityAuditEvent singleEventFor(String principal, SecurityAuditEventType type,
                                            SecurityAuditOutcome outcome) {
    List<SecurityAuditEvent> matches = auditRepository
        .search(null, type, outcome, PageRequest.of(0, 1000, Sort.by(Sort.Direction.DESC, "createdAt")))
        .getContent().stream()
        .filter(e -> principal.equals(e.getPrincipal()))
        .toList();
    assertEquals(1, matches.size(),
        "exactly one " + type + "/" + outcome + " row must exist for " + principal);
    return matches.get(0);
  }
}
