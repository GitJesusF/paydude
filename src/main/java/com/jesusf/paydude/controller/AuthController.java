package com.jesusf.paydude.controller;

import com.jesusf.paydude.config.web.ApiV1;
import com.jesusf.paydude.dto.auth.AuthResponse;
import com.jesusf.paydude.dto.auth.LoginRequest;
import com.jesusf.paydude.dto.auth.LoginResult;
import com.jesusf.paydude.dto.auth.LogoutRequest;
import com.jesusf.paydude.dto.auth.MfaChallengeResponse;
import com.jesusf.paydude.dto.auth.MfaVerifyRequest;
import com.jesusf.paydude.dto.auth.RefreshTokenRequest;
import com.jesusf.paydude.dto.auth.RegisterRequest;
import com.jesusf.paydude.exception.RateLimitExceededException;
import com.jesusf.paydude.security.ratelimit.AuthRateLimiter;
import com.jesusf.paydude.security.ratelimit.IpRateLimitFilter;
import com.jesusf.paydude.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Auth endpoints. The IP-keyed throttle is enforced upstream by {@link IpRateLimitFilter}; this
 * controller is responsible only for the email-keyed throttle (which needs the parsed body),
 * the refund on successful login (which needs the authentication outcome), and the
 * audit-context propagation (IP + User-Agent) to {@link AuthService} for refresh-token rows.
 *
 * <p>These endpoints are public (no bearer token). Every error response uses the RFC 9457
 * {@code application/problem+json} shape ({@link ProblemDetail}); a {@code 429} additionally
 * carries a {@code Retry-After} header.
 */
@RestController
@RequestMapping("/auth")
@ApiV1
@RequiredArgsConstructor
@Tag(name = "Auth", description = "Authentication and session lifecycle. Token operations align with RFC 6749 (OAuth 2.0) for issuance and RFC 7009 (OAuth 2.0 Token Revocation) for logout.")
public class AuthController {

  private static final String USER_AGENT_HEADER = "User-Agent";

  private final AuthService authService;
  private final AuthRateLimiter rateLimiter;

  /**
   * Registers a new user, opens their default account, and issues the first token pair.
   *
   * @param request     the registration details
   * @param httpRequest the servlet request — IP and User-Agent are captured for the
   *                    refresh-token audit row
   * @return {@code 201 Created} with the access + refresh token pair
   */
  @Operation(
      summary = "Register a new user",
      description = "Creates the user and their default USD account, then issues an access + "
          + "refresh token pair. The password is screened against the HaveIBeenPwned breach corpus."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "User registered; tokens issued",
          content = @Content(schema = @Schema(implementation = AuthResponse.class))),
      @ApiResponse(responseCode = "400", description = "Invalid request body",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "409", description = "Email already registered, or the chosen "
          + "password appears in a known data-breach corpus",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "429", description = "Too many registration attempts from this IP",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @PostMapping("/register")
  @ResponseStatus(HttpStatus.CREATED)
  public ResponseEntity<AuthResponse> register(
      @Valid @RequestBody RegisterRequest request,
      HttpServletRequest httpRequest
  ) {
    // IP + User-Agent travel into the refresh-token audit row. With server.forward-headers-strategy
    // set in prod, getRemoteAddr() returns the real client IP — see docs/patterns.md #18 (layered
    // rate limiting) for the trust-model details.
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(authService.register(request, clientIp(httpRequest), userAgent(httpRequest)));
  }

  /**
   * Authenticates credentials and issues a new token pair — or, for an MFA-enrolled account, the
   * step-up challenge that {@code POST /v1/auth/mfa/verify} completes.
   *
   * @param request     the login credentials
   * @param httpRequest the servlet request — IP and User-Agent are captured for the
   *                    refresh-token audit row
   * @return {@code 200 OK} with the token pair, or with an {@link MfaChallengeResponse} when a
   *         second factor is still owed (discriminated by the {@code mfaRequired} body field)
   */
  @Operation(
      summary = "Authenticate and obtain tokens",
      description = "Verifies the credentials and issues an access + refresh token pair. If the "
          + "account has TOTP enabled, returns an MFA challenge (mfaRequired=true) instead — "
          + "complete the login at /v1/auth/mfa/verify. "
          + "Throttled per IP and per email; a successful password check refunds the email bucket."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Authenticated (token pair), or password "
          + "accepted with a second factor still required (MFA challenge — see mfaRequired)",
          content = @Content(schema = @Schema(oneOf = {AuthResponse.class, MfaChallengeResponse.class}))),
      @ApiResponse(responseCode = "400", description = "Invalid request body",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "401", description = "Invalid credentials, or the account has "
          + "expired or its credentials have expired",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "403", description = "Account is disabled (suspended or closed)",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "423", description = "Account is locked",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "429", description = "Too many login attempts from this IP or "
          + "for this account",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @PostMapping("/login")
  public ResponseEntity<?> login(
      @Valid @RequestBody LoginRequest request,
      HttpServletRequest httpRequest
  ) {
    if (!rateLimiter.tryLoginByEmail(request.email())) {
      throw new RateLimitExceededException(
          "Too many failed attempts for this account. Try again in 15 minutes.", 900
      );
    }

    // The email bucket was already consumed above, so a failed authentication simply propagates and
    // stays counted; recordSuccessfulLogin refunds the token only on the non-exception path below.
    // The refund applies to BOTH outcomes: this bucket exists to absorb password typos, and an MFA
    // challenge means the password was correct. Guessing at the second factor is bounded elsewhere
    // (per-IP mfa bucket + persistent lockout), not by the password-typo budget.
    LoginResult result = authService.login(request, clientIp(httpRequest), userAgent(httpRequest));
    rateLimiter.recordSuccessfulLogin(request.email());
    // Exhaustive over the sealed interface — a future third outcome fails compilation here, not at
    // runtime. The two shapes share the 200 status; clients branch on the mfaRequired body field.
    return switch (result) {
      case LoginResult.Tokens(AuthResponse tokens) -> ResponseEntity.ok(tokens);
      case LoginResult.MfaRequired(MfaChallengeResponse challenge) -> ResponseEntity.ok(challenge);
    };
  }

  /**
   * Completes a step-up login: the challenge token from {@code /login} plus a TOTP or recovery
   * code buy the actual token pair.
   *
   * <p>Public like the other token endpoints (the challenge token in the body is the credential),
   * IP-throttled by {@link IpRateLimitFilter} under the {@code mfa} policy. There is no per-email
   * tier here on purpose: the failure path already feeds the <b>persistent</b> account lockout
   * (failed codes count exactly like failed passwords), which is the stronger per-account bound.
   *
   * @param request     the challenge token and the 6-digit TOTP (or recovery) code
   * @param httpRequest the servlet request — IP and User-Agent are captured for the
   *                    refresh-token audit row
   * @return {@code 200 OK} with the access + refresh token pair
   */
  @Operation(
      summary = "Complete an MFA login",
      description = "Verifies the second factor for a pending step-up login: the mfaToken issued "
          + "by /v1/auth/login plus a 6-digit TOTP code — or a single-use recovery code for the "
          + "lost-device path. On success issues the access + refresh token pair. Wrong codes "
          + "count toward the same account lockout as wrong passwords."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Second factor verified; tokens issued",
          content = @Content(schema = @Schema(implementation = AuthResponse.class))),
      @ApiResponse(responseCode = "400", description = "Invalid request body",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "401", description = "Challenge token invalid or expired, or "
          + "the code is wrong, replayed, or already used",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "403", description = "Account is disabled (suspended or closed)",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "423", description = "Account is locked (too many failed codes)",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "429", description = "Too many MFA attempts from this IP",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @PostMapping("/mfa/verify")
  public ResponseEntity<AuthResponse> verifyMfa(
      @Valid @RequestBody MfaVerifyRequest request,
      HttpServletRequest httpRequest
  ) {
    return ResponseEntity.ok(authService.verifyMfa(
        request, clientIp(httpRequest), userAgent(httpRequest)));
  }

  /**
   * Rotates the presented refresh token. The IP throttle for this path lives in
   * {@link IpRateLimitFilter}, so by the time we reach the controller the request has already
   * passed the volumetric check.
   *
   * @param request     the refresh token to rotate
   * @param httpRequest the servlet request — IP and User-Agent are captured for the new
   *                    refresh-token audit row
   * @return {@code 200 OK} with a fresh access + refresh token pair
   */
  @Operation(
      summary = "Rotate a refresh token",
      description = "Validates the presented refresh token, revokes it, and issues a fresh "
          + "access + refresh pair in the same family. Reusing an already-revoked token revokes "
          + "the whole family (reuse detection)."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Token rotated; fresh pair issued",
          content = @Content(schema = @Schema(implementation = AuthResponse.class))),
      @ApiResponse(responseCode = "400", description = "Invalid request body",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "401", description = "Refresh token is unknown, expired, or "
          + "already revoked (reuse detected)",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "403", description = "The owning account is no longer active",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "429", description = "Too many refresh attempts from this IP",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @PostMapping("/refresh")
  public ResponseEntity<AuthResponse> refresh(
      @Valid @RequestBody RefreshTokenRequest request,
      HttpServletRequest httpRequest
  ) {
    return ResponseEntity.ok(authService.refresh(
        request.refreshToken(),
        clientIp(httpRequest),
        userAgent(httpRequest)
    ));
  }

  /**
   * Revokes the family of the presented refresh token. Idempotent: any value (or even an unknown
   * one) returns 204. We deliberately do not gate this on rate-limit — a user that wants to log
   * out should always succeed.
   *
   * @param request the refresh token whose family should be revoked
   */
  @Operation(
      summary = "Revoke a refresh token (logout)",
      description = """
          RFC 7009-aligned token revocation. The presented refresh token, plus every other token in
          its rotation family, is invalidated atomically — logging out from one device terminates
          every session that descends from the same original login.

          Idempotent at the application layer: revoking an already-revoked family, or presenting an
          unknown token, also returns 204 No Content. This is required by RFC 7009 §2.2, which
          notes that invalid tokens MUST NOT produce an error response — both because the goal
          (the token cannot be used) is already achieved, and because differentiating known vs
          unknown tokens would turn the endpoint into a token-validity oracle for enumeration.

          Not rate-limited. Throttling logout would let an attacker who exhausts a user's bucket
          deny them the ability to terminate a compromised session, which is the opposite of the
          security property the endpoint exists to provide. The currently-issued access token
          remains valid until its natural expiry (~15 min, the stateless-JWT trade-off); the
          refresh path is what is closed immediately.
          """
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Family revoked (or already invalid)",
          content = @Content),
      @ApiResponse(responseCode = "400", description = "Invalid request body",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @PostMapping("/logout")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void logout(@Valid @RequestBody LogoutRequest request) {
    authService.logout(request.refreshToken());
  }

  private static String clientIp(HttpServletRequest httpRequest) {
    return httpRequest.getRemoteAddr();
  }

  private static String userAgent(HttpServletRequest httpRequest) {
    return httpRequest.getHeader(USER_AGENT_HEADER);
  }
}
