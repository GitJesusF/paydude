package com.jesusf.paydude.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jesusf.paydude.dto.auth.AuthResponse;
import com.jesusf.paydude.dto.auth.LoginRequest;
import com.jesusf.paydude.dto.auth.LoginResult;
import com.jesusf.paydude.dto.auth.LogoutRequest;
import com.jesusf.paydude.dto.auth.MfaChallengeResponse;
import com.jesusf.paydude.dto.auth.MfaVerifyRequest;
import com.jesusf.paydude.dto.auth.RefreshTokenRequest;
import com.jesusf.paydude.dto.auth.RegisterRequest;
import com.jesusf.paydude.security.CustomUserDetailsService;
import com.jesusf.paydude.security.JwtService;
import com.jesusf.paydude.security.ratelimit.AuthRateLimiter;
import com.jesusf.paydude.service.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web-layer tests for {@link AuthController}.
 *
 * <p>Covers the public auth endpoints: register and login mint an access + refresh pair (RFC 6749
 * §5.1 + RFC 6749 §1.5); refresh rotates the presented refresh token; logout revokes its family
 * idempotently. Bean Validation errors short-circuit the service call with a 400 + ProblemDetail
 * in all four cases. The rate limiter is mocked to allow every request through; its negative
 * behavior is exercised in {@code AuthRateLimiterTest} and {@code IpRateLimitFilterTest}.
 */
@WebMvcTest(controllers = AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

  private static final long EXPIRES_IN = 900L;          // 15 min, matches dev default
  private static final long REFRESH_EXPIRES_IN = 604800L; // 7 days, matches dev default

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private ObjectMapper objectMapper;

  @MockitoBean
  private AuthService authService;

  // SecurityConfig requires these to build the context even though addFilters=false disables the
  // chain at runtime; without the mocks the slice fails with "No qualifying bean of type ...".
  @MockitoBean
  private JwtService jwtService;

  @MockitoBean
  private CustomUserDetailsService userDetailsService;

  // The controller consumes the per-email throttle (the per-IP tier lives in IpRateLimitFilter,
  // disabled by addFilters=false). Mocked to admit every request; AuthRateLimiterTest covers it.
  @MockitoBean
  private AuthRateLimiter authRateLimiter;

  @Test
  @DisplayName("POST /auth/register - returns 201 Created with access + refresh tokens")
  void shouldRegisterUser() throws Exception {
    RegisterRequest request = new RegisterRequest("Jesus", "Dev", "jesus@test.com", "pass1234");
    AuthResponse mockResponse = new AuthResponse(
        "token-xyz", "Bearer", EXPIRES_IN, "refresh-xyz", REFRESH_EXPIRES_IN
    );

    when(authService.register(any(RegisterRequest.class), anyString(), any()))
        .thenReturn(mockResponse);

    mockMvc.perform(post("/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isCreated())
        // Pin all five OAuth-style fields so a refactor cannot silently truncate the response.
        .andExpect(jsonPath("$.accessToken").value("token-xyz"))
        .andExpect(jsonPath("$.tokenType").value("Bearer"))
        .andExpect(jsonPath("$.expiresIn").value(EXPIRES_IN))
        .andExpect(jsonPath("$.refreshToken").value("refresh-xyz"))
        .andExpect(jsonPath("$.refreshExpiresIn").value(REFRESH_EXPIRES_IN));
  }

  @Test
  @DisplayName("POST /auth/register - 400 Bad Request on invalid input")
  void shouldReturn400OnInvalidInput() throws Exception {
    RegisterRequest invalidRequest = new RegisterRequest("", "", "not-an-email", "");

    mockMvc.perform(post("/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(invalidRequest)))

        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.title").value("Validation Error"))
        .andExpect(jsonPath("$.type").value("/problems/validation-error"))
        .andExpect(jsonPath("$.status").value(400))
        .andExpect(jsonPath("$.errors.firstName").exists())
        .andExpect(jsonPath("$.errors.email").exists());
  }

  @Test
  @DisplayName("POST /auth/login - returns 200 OK with access + refresh tokens")
  void shouldLoginUser() throws Exception {
    LoginRequest request = new LoginRequest("jesus@test.com", "pass1234");
    AuthResponse mockResponse = new AuthResponse(
        "login-token", "Bearer", EXPIRES_IN, "login-refresh", REFRESH_EXPIRES_IN
    );

    // Mockito's boolean default is false — without this stub the controller would answer 429
    // before ever reaching the service.
    when(authRateLimiter.tryLoginByEmail(anyString())).thenReturn(true);
    when(authService.login(any(LoginRequest.class), anyString(), any()))
        .thenReturn(new LoginResult.Tokens(mockResponse));

    mockMvc.perform(post("/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accessToken").value("login-token"))
        .andExpect(jsonPath("$.refreshToken").value("login-refresh"));
  }

  @Test
  @DisplayName("POST /auth/login - 429 with Retry-After when the per-email throttle is exhausted")
  void shouldReturn429WhenLoginThrottled() throws Exception {
    LoginRequest request = new LoginRequest("jesus@test.com", "pass1234");

    // Explicit even though false is Mockito's boolean default: the drained bucket is the very
    // condition under test.
    when(authRateLimiter.tryLoginByEmail(anyString())).thenReturn(false);

    mockMvc.perform(post("/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isTooManyRequests())
        .andExpect(header().exists("Retry-After"))
        .andExpect(jsonPath("$.status").value(429));

    // The throttle fires before any authentication work — BCrypt is never paid for.
    verifyNoInteractions(authService);
  }

  @Test
  @DisplayName("POST /auth/login - 400 Bad Request when fields are blank")
  void shouldReturn400OnBlankLoginFields() throws Exception {
    LoginRequest invalid = new LoginRequest("", "");

    mockMvc.perform(post("/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(invalid)))

        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.errors.email").exists())
        .andExpect(jsonPath("$.errors.password").exists());
  }

  @Test
  @DisplayName("POST /auth/login - 200 with the MFA challenge shape when the account is enrolled")
  void shouldReturnMfaChallengeShape() throws Exception {
    LoginRequest request = new LoginRequest("jesus@test.com", "pass1234");

    when(authRateLimiter.tryLoginByEmail(anyString())).thenReturn(true);
    // MfaRequired branch: correct password, second factor pending — same 200, different body
    // shape, discriminated by the mfaRequired field.
    when(authService.login(any(LoginRequest.class), anyString(), any()))
        .thenReturn(new LoginResult.MfaRequired(
            new MfaChallengeResponse(true, "challenge-jwt", 300L)));

    mockMvc.perform(post("/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isOk())
        // Pin the three challenge keys AND the absence of tokens: leaking an accessToken on this
        // branch would break the step-up as a security control.
        .andExpect(jsonPath("$.mfaRequired").value(true))
        .andExpect(jsonPath("$.mfaToken").value("challenge-jwt"))
        .andExpect(jsonPath("$.expiresIn").value(300))
        .andExpect(jsonPath("$.accessToken").doesNotExist())
        .andExpect(jsonPath("$.refreshToken").doesNotExist());
  }

  @Test
  @DisplayName("POST /auth/mfa/verify - returns 200 OK with the token pair")
  void shouldCompleteMfaLogin() throws Exception {
    MfaVerifyRequest request = new MfaVerifyRequest("challenge-jwt", "123456");
    AuthResponse mockResponse = new AuthResponse(
        "mfa-access", "Bearer", EXPIRES_IN, "mfa-refresh", REFRESH_EXPIRES_IN
    );

    when(authService.verifyMfa(any(MfaVerifyRequest.class), anyString(), any()))
        .thenReturn(mockResponse);

    mockMvc.perform(post("/v1/auth/mfa/verify")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accessToken").value("mfa-access"))
        .andExpect(jsonPath("$.refreshToken").value("mfa-refresh"));
  }

  @Test
  @DisplayName("POST /auth/mfa/verify - 401 when the code or challenge is rejected")
  void shouldReturn401OnRejectedMfa() throws Exception {
    MfaVerifyRequest request = new MfaVerifyRequest("challenge-jwt", "000000");

    doThrow(new BadCredentialsException("Invalid MFA code"))
        .when(authService).verifyMfa(any(MfaVerifyRequest.class), anyString(), any());

    mockMvc.perform(post("/v1/auth/mfa/verify")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.status").value(401));
  }

  @Test
  @DisplayName("POST /auth/mfa/verify - 400 Bad Request when fields are blank")
  void shouldReturn400OnBlankMfaFields() throws Exception {
    MfaVerifyRequest invalid = new MfaVerifyRequest("", "");

    mockMvc.perform(post("/v1/auth/mfa/verify")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(invalid)))

        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.errors.mfaToken").exists())
        .andExpect(jsonPath("$.errors.code").exists());
  }

  @Test
  @DisplayName("POST /auth/refresh - rotates the token and returns a fresh pair")
  void shouldRefreshTokens() throws Exception {
    RefreshTokenRequest request = new RefreshTokenRequest("old-refresh-token");
    AuthResponse mockResponse = new AuthResponse(
        "rotated-access", "Bearer", EXPIRES_IN, "rotated-refresh", REFRESH_EXPIRES_IN
    );

    when(authService.refresh(eq("old-refresh-token"), anyString(), any())).thenReturn(mockResponse);

    mockMvc.perform(post("/v1/auth/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accessToken").value("rotated-access"))
        .andExpect(jsonPath("$.refreshToken").value("rotated-refresh"))
        .andExpect(jsonPath("$.expiresIn").value(EXPIRES_IN))
        .andExpect(jsonPath("$.refreshExpiresIn").value(REFRESH_EXPIRES_IN));
  }

  @Test
  @DisplayName("POST /auth/refresh - 401 when the service rejects the token (reuse, expired, unknown)")
  void shouldReturn401WhenRefreshRejected() throws Exception {
    RefreshTokenRequest request = new RefreshTokenRequest("bad-token");

    doThrow(new BadCredentialsException("Refresh token reuse detected"))
        .when(authService).refresh(anyString(), anyString(), any());

    mockMvc.perform(post("/v1/auth/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isUnauthorized())
        // The body must not leak the failure mode; the specific message is for server logs only.
        .andExpect(jsonPath("$.status").value(401));
  }

  @Test
  @DisplayName("POST /auth/refresh - 400 Bad Request when refreshToken is blank")
  void shouldReturn400OnBlankRefreshToken() throws Exception {
    RefreshTokenRequest invalid = new RefreshTokenRequest("");

    mockMvc.perform(post("/v1/auth/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(invalid)))

        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.errors.refreshToken").exists());
  }

  @Test
  @DisplayName("POST /auth/logout - returns 204 No Content and delegates to the service")
  void shouldLogout() throws Exception {
    LogoutRequest request = new LogoutRequest("any-refresh-token");

    mockMvc.perform(post("/v1/auth/logout")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))

        .andExpect(status().isNoContent());

    verify(authService).logout("any-refresh-token");
  }

  @Test
  @DisplayName("POST /auth/logout - 400 Bad Request when refreshToken is blank")
  void shouldReturn400OnBlankLogoutToken() throws Exception {
    LogoutRequest invalid = new LogoutRequest("");

    mockMvc.perform(post("/v1/auth/logout")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(invalid)))

        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.errors.refreshToken").exists());
  }
}
