package com.jesusf.paydude.controller;

import com.jesusf.paydude.support.WithMockSecurityUser;
import com.jesusf.paydude.dto.user.UserResponse;
import com.jesusf.paydude.exception.RateLimitExceededException;
import com.jesusf.paydude.exception.ResourceNotFoundException;
import com.jesusf.paydude.security.CustomUserDetailsService;
import com.jesusf.paydude.security.JwtService;
import com.jesusf.paydude.security.ratelimit.AuthRateLimiter;
import com.jesusf.paydude.security.ratelimit.ReauthRateLimiter;
import com.jesusf.paydude.service.UserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web-layer tests for {@link UserController}.
 *
 * <p>Exercises {@code GET /v1/users/me}: that the authenticated principal's id is propagated
 * to {@link UserService#getCurrentUser}, that the resulting DTO is serialized into the
 * expected JSON shape, and that a missing user surfaces as a 404 with the project's
 * {@code ProblemDetail} JSON. The JWT filter is disabled at slice level so each test can
 * inject a principal via {@code @WithMockSecurityUser} without a real token.
 */
@WebMvcTest(controllers = UserController.class)
@AutoConfigureMockMvc(addFilters = false)
class UserControllerTest {

  // Matches @WithMockSecurityUser's default id, so eq(MOCK_USER_ID) stubs always line up with
  // the injected principal.
  private static final Long MOCK_USER_ID = 1L;

  @Autowired private MockMvc mockMvc;

  @MockitoBean private UserService userService;
  // jwtService/userDetailsService: SecurityConfig requires them to build the context even with
  // addFilters=false. authRateLimiter: the slice scans all Filter @Components, so
  // IpRateLimitFilter is constructed (though never run) and its dependency must be satisfied.
  @MockitoBean private JwtService jwtService;
  @MockitoBean private CustomUserDetailsService userDetailsService;
  @MockitoBean private AuthRateLimiter authRateLimiter;
  // Direct dependency of UserController: the per-user throttle on the password re-auth gate. Its
  // enforceReauthByUser is void, so Mockito's default (do nothing) lets the happy paths through; the
  // throttling test below uses doThrow to force the 429.
  @MockitoBean private ReauthRateLimiter reauthRateLimiter;

  @Test
  @DisplayName("GET /users/me - Should return 200 with the authenticated user's profile")
  @WithMockSecurityUser
  void shouldReturnCurrentUserProfile() throws Exception {
    UserResponse mockResponse = new UserResponse(
        MOCK_USER_ID, "Jesus", "Dev", "test@test.com", "ROLE_USER", "ACTIVE"
    );

    when(userService.getCurrentUser(eq(MOCK_USER_ID))).thenReturn(mockResponse);

    mockMvc.perform(get("/v1/users/me"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id").value(MOCK_USER_ID))
        .andExpect(jsonPath("$.firstName").value("Jesus"))
        .andExpect(jsonPath("$.lastName").value("Dev"))
        .andExpect(jsonPath("$.email").value("test@test.com"))
        .andExpect(jsonPath("$.role").value("ROLE_USER"))
        .andExpect(jsonPath("$.status").value("ACTIVE"));
  }

  @Test
  @DisplayName("GET /users/me - Should propagate 404 when the principal no longer exists")
  @WithMockSecurityUser
  void shouldReturn404WhenUserNoLongerExists() throws Exception {
    // The JWT is still valid (signature and exp OK) but the user is gone — the filter trusts
    // claims and never re-reads the DB, so only the service load detects the orphaned id.
    when(userService.getCurrentUser(eq(MOCK_USER_ID)))
        .thenThrow(new ResourceNotFoundException("User not found: " + MOCK_USER_ID));

    mockMvc.perform(get("/v1/users/me"))
        .andExpect(status().isNotFound())
        // RFC 9457 ProblemDetail contract: the four standard fields a client may consume.
        .andExpect(jsonPath("$.title").value("Not Found"))
        .andExpect(jsonPath("$.detail").value("User not found: " + MOCK_USER_ID))
        .andExpect(jsonPath("$.status").value(404))
        .andExpect(jsonPath("$.type").value("/problems/not-found"));
  }

  @Test
  @DisplayName("PATCH /users/me/password - returns 204 No Content on successful rotation")
  @WithMockSecurityUser
  void shouldChangePasswordReturning204() throws Exception {
    String body = """
        {"currentPassword":"plain-old","newPassword":"plain-new-12345"}
        """;

    mockMvc.perform(patch("/v1/users/me/password")
            .contentType(MediaType.APPLICATION_JSON)
            .content(body))
        .andExpect(status().isNoContent());

    verify(userService).changePassword(MOCK_USER_ID, "plain-old", "plain-new-12345");
  }

  @Test
  @DisplayName("PATCH /users/me/password - returns 400 when payload fails validation")
  @WithMockSecurityUser
  void shouldReturn400OnInvalidPayload() throws Exception {
    // Empty currentPassword fails @NotBlank; a 3-char newPassword fails @Size — Bean Validation
    // cuts the flow before the service, so nothing is stubbed.
    String body = """
        {"currentPassword":"","newPassword":"123"}
        """;

    mockMvc.perform(patch("/v1/users/me/password")
            .contentType(MediaType.APPLICATION_JSON)
            .content(body))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.errors.currentPassword").exists())
        .andExpect(jsonPath("$.errors.newPassword").exists());
  }

  @Test
  @DisplayName("PATCH /users/me/password - propagates 401 when current password mismatches")
  @WithMockSecurityUser
  void shouldReturn401WhenCurrentPasswordWrong() throws Exception {
    doThrow(new BadCredentialsException("Current password does not match"))
        .when(userService).changePassword(eq(MOCK_USER_ID), eq("wrong"), eq("plain-new-12345"));

    String body = """
        {"currentPassword":"wrong","newPassword":"plain-new-12345"}
        """;

    mockMvc.perform(patch("/v1/users/me/password")
            .contentType(MediaType.APPLICATION_JSON)
            .content(body))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.status").value(401));
  }

  @Test
  @DisplayName("PATCH /users/me/password - returns 429 when the re-auth throttle is exhausted")
  @WithMockSecurityUser
  void shouldReturn429WhenReauthThrottled() throws Exception {
    // The per-user throttle applies before the service runs: a stolen bearer token must not
    // brute-force the password at BCrypt speed, and the IP/email auth buckets do not cover
    // this endpoint.
    doThrow(new RateLimitExceededException("Too many password-change attempts.", 900))
        .when(reauthRateLimiter).enforceReauthByUser(eq(MOCK_USER_ID), anyString());

    String body = """
        {"currentPassword":"plain-old","newPassword":"plain-new-12345"}
        """;

    mockMvc.perform(patch("/v1/users/me/password")
            .contentType(MediaType.APPLICATION_JSON)
            .content(body))
        .andExpect(status().isTooManyRequests())
        .andExpect(jsonPath("$.status").value(429));

    // The gate short-circuits before any service work — the guarantee under test.
    verifyNoInteractions(userService);
  }
}
