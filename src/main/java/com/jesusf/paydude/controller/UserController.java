package com.jesusf.paydude.controller;

import com.jesusf.paydude.config.web.ApiV1;
import com.jesusf.paydude.dto.user.ChangePasswordRequest;
import com.jesusf.paydude.dto.user.UserResponse;
import com.jesusf.paydude.security.SecurityUser;
import com.jesusf.paydude.security.ratelimit.ReauthRateLimiter;
import com.jesusf.paydude.service.UserService;
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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP endpoints for the authenticated user's own profile. Mounted under {@code /v1/users}.
 *
 * <p>Profile data is served here, separate from the token endpoints, so {@code /auth/login} can
 * stay free of PII and a JWT never has to carry it — the OAuth-style split between token
 * issuance and profile retrieval.
 *
 * <p>Every error response uses the RFC 9457 {@code application/problem+json} shape
 * ({@link ProblemDetail}).
 */
@RestController
@RequestMapping("/users")
@ApiV1
@RequiredArgsConstructor
@Tag(name = "Users", description = "Authenticated user profile endpoints")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

  private final UserService userService;
  // Per-user throttle on the password-re-authentication gate below. This endpoint verifies the
  // current password behind a bearer token but is not covered by the IP/email auth throttles, so
  // without this a stolen token could brute-force the password unbounded (see ReauthRateLimiter).
  private final ReauthRateLimiter reauthRateLimiter;

  /**
   * Returns the profile of the user owning the bearer token.
   *
   * @param principal the authenticated user
   * @return {@code 200 OK} with the user's profile
   */
  @Operation(
      summary = "Get the authenticated user's profile",
      description = "Returns identity and role information for the user owning the bearer token. "
          + "Intended to be the second call after /auth/login, completing the OAuth-style flow "
          + "where the token endpoint stays free of profile data."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Profile returned",
          content = @Content(schema = @Schema(implementation = UserResponse.class))),
      @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "404", description = "User not found",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @GetMapping("/me")
  public ResponseEntity<UserResponse> getCurrentUser(
      @AuthenticationPrincipal SecurityUser principal
  ) {
    return ResponseEntity.ok(userService.getCurrentUser(principal.id()));
  }

  /**
   * Changes the authenticated user's password.
   *
   * <p>The service verifies {@code currentPassword}, updates the stored hash and
   * {@code passwordChangedAt}, and revokes every refresh-token family for the user — so every
   * device, including the caller's, must re-login.
   *
   * @param principal the authenticated user
   * @param request   the current and new passwords
   */
  @Operation(
      summary = "Change the authenticated user's password",
      description = "Verifies the current password, updates the stored BCrypt hash, advances "
          + "passwordChangedAt (which feeds the optional credential-rotation policy), and "
          + "revokes every outstanding refresh-token family for this user — forcing re-login "
          + "on every device, including the one making this call. Returns 204 No Content."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Password changed; all sessions revoked",
          content = @Content),
      @ApiResponse(responseCode = "400", description = "Invalid request body (e.g. new password "
          + "too short)",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "401", description = "Missing or invalid access token, or the "
          + "supplied current password is incorrect",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "409", description = "The new password appears in a known "
          + "data-breach corpus (HaveIBeenPwned)",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @PatchMapping("/me/password")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void changePassword(
      @AuthenticationPrincipal SecurityUser principal,
      @Valid @RequestBody ChangePasswordRequest request
  ) {
    // Throttle the password re-auth before any BCrypt work, so a stolen token cannot brute-force
    // the current password at the endpoint the lockout/auth throttles do not cover.
    reauthRateLimiter.enforceReauthByUser(principal.id(),
        "Too many password-change attempts. Please slow down and try again shortly.");
    userService.changePassword(principal.id(), request.currentPassword(), request.newPassword());
  }
}
