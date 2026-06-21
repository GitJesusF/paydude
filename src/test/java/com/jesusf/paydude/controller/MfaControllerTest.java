package com.jesusf.paydude.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jesusf.paydude.dto.user.MfaConfirmRequest;
import com.jesusf.paydude.dto.user.MfaDisableRequest;
import com.jesusf.paydude.dto.user.MfaRecoveryCodesResponse;
import com.jesusf.paydude.dto.user.MfaSetupRequest;
import com.jesusf.paydude.dto.user.MfaSetupResponse;
import com.jesusf.paydude.exception.BusinessException;
import com.jesusf.paydude.exception.RateLimitExceededException;
import com.jesusf.paydude.security.CustomUserDetailsService;
import com.jesusf.paydude.security.JwtService;
import com.jesusf.paydude.security.ratelimit.AuthRateLimiter;
import com.jesusf.paydude.security.ratelimit.ReauthRateLimiter;
import com.jesusf.paydude.service.MfaService;
import com.jesusf.paydude.support.WithMockSecurityUser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web-layer tests for {@link MfaController}.
 *
 * <p>Covers the three TOTP-management endpoints under {@code /v1/users/me/mfa}: setup returns the
 * provisioning material, confirm returns the one-time recovery codes, disable returns 204. The
 * lifecycle rules themselves (password gate, pending state, single-use) are pinned in
 * {@code MfaServiceTest}; here the contract is HTTP: status codes, JSON shapes, Bean Validation
 * short-circuits, and the principal's id (never a body field) selecting the target account.
 */
@WebMvcTest(controllers = MfaController.class)
@AutoConfigureMockMvc(addFilters = false)
class MfaControllerTest {

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private ObjectMapper objectMapper;

  @MockitoBean
  private MfaService mfaService;

  // jwtService/userDetailsService: SecurityConfig requires them to build the context even with
  // addFilters=false. authRateLimiter: the slice scans all Filter @Components, so
  // IpRateLimitFilter is constructed (though never run) and its dependency must be satisfied.
  @MockitoBean
  private JwtService jwtService;

  @MockitoBean
  private CustomUserDetailsService userDetailsService;

  @MockitoBean
  private AuthRateLimiter authRateLimiter;

  // Direct dependency of MfaController: the per-user throttle on the password-gated setup/disable.
  // enforceReauthByUser is void, so Mockito's default lets the happy paths through; the throttling
  // test uses doThrow to force the 429.
  @MockitoBean
  private ReauthRateLimiter reauthRateLimiter;

  @Test
  @WithMockSecurityUser
  @DisplayName("POST /users/me/mfa/setup - 200 with the Base32 secret and otpauth URI")
  void shouldStartEnrollment() throws Exception {
    when(mfaService.setup(1L, "S3cure!pass")).thenReturn(new MfaSetupResponse(
        "JBSWY3DPEHPK3PXP", "otpauth://totp/PayDude:test%40test.com?secret=JBSWY3DPEHPK3PXP"));

    mockMvc.perform(post("/v1/users/me/mfa/setup")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(new MfaSetupRequest("S3cure!pass"))))

        .andExpect(status().isOk())
        .andExpect(jsonPath("$.secret").value("JBSWY3DPEHPK3PXP"))
        .andExpect(jsonPath("$.otpauthUri").value(
            "otpauth://totp/PayDude:test%40test.com?secret=JBSWY3DPEHPK3PXP"));

    // The userId comes from the token's principal (id=1 from @WithMockSecurityUser), never from
    // the body — there is no way to enroll MFA on another user's account.
    verify(mfaService).setup(1L, "S3cure!pass");
  }

  @Test
  @WithMockSecurityUser
  @DisplayName("POST /users/me/mfa/setup - 401 when the re-authentication password is wrong")
  void shouldReturn401OnWrongPassword() throws Exception {
    doThrow(new BadCredentialsException("Current password does not match"))
        .when(mfaService).setup(1L, "wrong");

    mockMvc.perform(post("/v1/users/me/mfa/setup")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(new MfaSetupRequest("wrong"))))

        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.status").value(401));
  }

  @Test
  @WithMockSecurityUser
  @DisplayName("POST /users/me/mfa/setup - 400 when the password is blank")
  void shouldReturn400OnBlankPassword() throws Exception {
    mockMvc.perform(post("/v1/users/me/mfa/setup")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(new MfaSetupRequest(""))))

        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.errors.password").exists());
  }

  @Test
  @WithMockSecurityUser
  @DisplayName("POST /users/me/mfa/confirm - 200 with the single-use recovery codes")
  void shouldConfirmEnrollment() throws Exception {
    when(mfaService.confirm(1L, "123456")).thenReturn(new MfaRecoveryCodesResponse(
        List.of("K7QW-2MNB-X4ZC", "P3RT-9LKJ-D6VS")));

    mockMvc.perform(post("/v1/users/me/mfa/confirm")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(new MfaConfirmRequest("123456"))))

        .andExpect(status().isOk())
        .andExpect(jsonPath("$.recoveryCodes.length()").value(2))
        .andExpect(jsonPath("$.recoveryCodes[0]").value("K7QW-2MNB-X4ZC"));
  }

  @Test
  @WithMockSecurityUser
  @DisplayName("POST /users/me/mfa/confirm - 409 when the verification code is wrong")
  void shouldReturn409OnWrongCode() throws Exception {
    doThrow(new BusinessException("Invalid verification code"))
        .when(mfaService).confirm(1L, "000000");

    mockMvc.perform(post("/v1/users/me/mfa/confirm")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(new MfaConfirmRequest("000000"))))

        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.status").value(409));
  }

  @Test
  @WithMockSecurityUser
  @DisplayName("POST /users/me/mfa/confirm - 400 when the code is not exactly 6 digits")
  void shouldReturn400OnMalformedCode() throws Exception {
    mockMvc.perform(post("/v1/users/me/mfa/confirm")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(new MfaConfirmRequest("12ab56"))))

        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.errors.code").exists());
  }

  @Test
  @WithMockSecurityUser
  @DisplayName("POST /users/me/mfa/disable - 204 No Content and delegates to the service")
  void shouldDisable() throws Exception {
    mockMvc.perform(post("/v1/users/me/mfa/disable")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(new MfaDisableRequest("S3cure!pass"))))

        .andExpect(status().isNoContent());

    verify(mfaService).disable(1L, "S3cure!pass");
  }

  @Test
  @WithMockSecurityUser
  @DisplayName("POST /users/me/mfa/setup - 429 when the re-auth throttle is exhausted")
  void shouldReturn429WhenReauthThrottled() throws Exception {
    // setup re-verifies the account password behind the bearer token; the per-user throttle
    // applies before the service so a stolen token cannot brute-force that password at BCrypt
    // speed on an endpoint the IP/email auth buckets do not cover.
    doThrow(new RateLimitExceededException("Too many MFA management attempts.", 900))
        .when(reauthRateLimiter).enforceReauthByUser(eq(1L), anyString());

    mockMvc.perform(post("/v1/users/me/mfa/setup")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(new MfaSetupRequest("S3cure!pass"))))

        .andExpect(status().isTooManyRequests())
        .andExpect(jsonPath("$.status").value(429));

    // The gate short-circuits before any service work — the guarantee under test.
    verifyNoInteractions(mfaService);
  }

  @Test
  @WithMockSecurityUser
  @DisplayName("POST /users/me/mfa/confirm - 429 when the re-auth throttle is exhausted")
  void shouldReturn429WhenConfirmThrottled() throws Exception {
    // confirm checks a 6-digit code (~3 valid per attempt in the ±1 window) and a hit returns
    // the recovery codes; its wrong-code 409s feed no lockout, so this bucket is the only bound
    // against guessing it online with a stolen bearer token.
    doThrow(new RateLimitExceededException("Too many MFA management attempts.", 900))
        .when(reauthRateLimiter).enforceReauthByUser(eq(1L), anyString());

    mockMvc.perform(post("/v1/users/me/mfa/confirm")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(new MfaConfirmRequest("123456"))))

        .andExpect(status().isTooManyRequests())
        .andExpect(jsonPath("$.status").value(429));

    verifyNoInteractions(mfaService);
  }
}
