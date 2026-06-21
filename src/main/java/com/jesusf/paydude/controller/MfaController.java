package com.jesusf.paydude.controller;

import com.jesusf.paydude.config.web.ApiV1;
import com.jesusf.paydude.dto.user.MfaConfirmRequest;
import com.jesusf.paydude.dto.user.MfaDisableRequest;
import com.jesusf.paydude.dto.user.MfaRecoveryCodesResponse;
import com.jesusf.paydude.dto.user.MfaSetupRequest;
import com.jesusf.paydude.dto.user.MfaSetupResponse;
import com.jesusf.paydude.security.SecurityUser;
import com.jesusf.paydude.security.ratelimit.ReauthRateLimiter;
import com.jesusf.paydude.service.MfaService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * TOTP second-factor management for the authenticated user. Mounted under
 * {@code /v1/users/me/mfa} — these are account-security settings, a sibling of the password
 * change on {@code UserController}, not part of the public token surface (which only hosts the
 * login-time {@code /v1/auth/mfa/verify}).
 *
 * <p>All three operations are {@code POST}: setup and confirm create state, and disable takes a
 * request body (the re-authentication password) — which RFC 9110 §9.3.5 leaves without defined
 * semantics on {@code DELETE}, so a {@code POST /disable} action route is the standards-friendly
 * shape.
 *
 * <p>Every error response uses the RFC 9457 {@code application/problem+json} shape
 * ({@link ProblemDetail}).
 */
@RestController
@RequestMapping("/users/me/mfa")
@ApiV1
@RequiredArgsConstructor
@Tag(name = "MFA", description = "TOTP second-factor enrollment and removal (RFC 6238). "
    + "Setup and disable require the account password — a bearer token alone can neither enroll "
    + "an authenticator nor downgrade the account to single-factor.")
@SecurityRequirement(name = "bearerAuth")
public class MfaController {

  private final MfaService mfaService;
  // Per-user throttle on all three operations. setup/disable re-verify the account password behind
  // a bearer token but are not covered by the IP/email auth throttles, so without this a stolen
  // token could brute-force the password unbounded (see ReauthRateLimiter). confirm verifies a
  // 6-digit code, not the password — but an unthrottled confirm is the one online-guessable
  // surface (~3 valid codes per attempt in the ±1-step window) whose prize is the recovery-code
  // batch, and its wrong-code 409s feed neither the lockout nor any other bucket. Same per-user
  // budget for all three: these are rare, human-paced account-security actions.
  private final ReauthRateLimiter reauthRateLimiter;

  private static final String REAUTH_THROTTLE_MESSAGE =
      "Too many MFA management attempts. Please slow down and try again shortly.";

  /**
   * Starts TOTP enrollment: returns the provisioning secret/URI. Nothing is armed until
   * {@link #confirm} proves the authenticator works.
   *
   * @param principal the authenticated user
   * @param request   the account password (re-authentication)
   * @return {@code 200 OK} with the Base32 secret and {@code otpauth://} URI
   */
  @Operation(
      summary = "Start TOTP enrollment",
      description = "Verifies the account password, generates a fresh RFC 6238 secret and returns "
          + "it as a Base32 string plus an otpauth:// provisioning URI (render it as a QR code). "
          + "Enrollment stays pending — and login stays single-factor — until /confirm receives a "
          + "valid code. Calling setup again replaces the pending secret."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Pending enrollment created; provisioning "
          + "material returned (the secret is shown only here)",
          content = @Content(schema = @Schema(implementation = MfaSetupResponse.class))),
      @ApiResponse(responseCode = "400", description = "Invalid request body",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "401", description = "Missing/invalid access token, or the "
          + "supplied password is incorrect",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "409", description = "MFA is already enabled — disable it first",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "429", description = "Too many MFA management attempts",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @PostMapping("/setup")
  public ResponseEntity<MfaSetupResponse> setup(
      @AuthenticationPrincipal SecurityUser principal,
      @Valid @RequestBody MfaSetupRequest request
  ) {
    reauthRateLimiter.enforceReauthByUser(principal.id(), REAUTH_THROTTLE_MESSAGE);
    return ResponseEntity.ok(mfaService.setup(principal.id(), request.password()));
  }

  /**
   * Activates the pending enrollment with a code from the freshly-provisioned authenticator and
   * returns the single-use recovery codes.
   *
   * @param principal the authenticated user
   * @param request   a current 6-digit TOTP code
   * @return {@code 200 OK} with the recovery codes — displayed exactly once
   */
  @Operation(
      summary = "Activate TOTP",
      description = "Verifies a 6-digit code computed from the pending secret and switches the "
          + "account to MFA-required login. Returns the single-use recovery codes for the "
          + "lost-device path — they are shown exactly once and stored only as hashes."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "MFA enabled; recovery codes returned",
          content = @Content(schema = @Schema(implementation = MfaRecoveryCodesResponse.class))),
      @ApiResponse(responseCode = "400", description = "Invalid request body",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "409", description = "No pending setup, MFA already enabled, "
          + "or the verification code is wrong",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "429", description = "Too many MFA management attempts",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @PostMapping("/confirm")
  public ResponseEntity<MfaRecoveryCodesResponse> confirm(
      @AuthenticationPrincipal SecurityUser principal,
      @Valid @RequestBody MfaConfirmRequest request
  ) {
    // Throttled like setup/disable: confirm is brute-forceable (6-digit space) and a successful
    // guess returns the recovery codes — see the ReauthRateLimiter field comment.
    reauthRateLimiter.enforceReauthByUser(principal.id(), REAUTH_THROTTLE_MESSAGE);
    return ResponseEntity.ok(mfaService.confirm(principal.id(), request.code()));
  }

  /**
   * Disables the second factor after re-verifying the password. Idempotent — 204 whether or not
   * the account was enrolled.
   *
   * @param principal the authenticated user
   * @param request   the account password (re-authentication)
   */
  @Operation(
      summary = "Disable TOTP",
      description = "Verifies the account password, then removes the second factor: clears the "
          + "secret and deletes every recovery code. Idempotent at the application layer — "
          + "disabling a non-enrolled account also returns 204."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "MFA disabled (or was not enabled)",
          content = @Content),
      @ApiResponse(responseCode = "400", description = "Invalid request body",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "401", description = "Missing/invalid access token, or the "
          + "supplied password is incorrect",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "429", description = "Too many MFA management attempts",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @PostMapping("/disable")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void disable(
      @AuthenticationPrincipal SecurityUser principal,
      @Valid @RequestBody MfaDisableRequest request
  ) {
    reauthRateLimiter.enforceReauthByUser(principal.id(), REAUTH_THROTTLE_MESSAGE);
    mfaService.disable(principal.id(), request.password());
  }
}
