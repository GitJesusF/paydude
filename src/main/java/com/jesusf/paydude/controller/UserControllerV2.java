package com.jesusf.paydude.controller;

import com.jesusf.paydude.config.web.ApiV2;
import com.jesusf.paydude.dto.user.UserResponseV2;
import com.jesusf.paydude.security.SecurityUser;
import com.jesusf.paydude.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Version 2 of the user profile endpoint. Mounted under {@code /v2/users} via the {@link ApiV2}
 * marker.
 *
 * <p>It exists to demonstrate additive API evolution: v2 returns every v1 field plus
 * {@code createdAt}. v1 ({@link UserController}) is left entirely untouched, so existing v1
 * clients keep working — the two versions are routed independently by {@code WebConfig}.
 *
 * <p>Every error response uses the RFC 9457 {@code application/problem+json} shape
 * ({@link ProblemDetail}).
 */
@RestController
@RequestMapping("/users")
@ApiV2
@RequiredArgsConstructor
@Tag(name = "Users (v2)", description = "Extended user profile — additive over v1")
@SecurityRequirement(name = "bearerAuth")
public class UserControllerV2 {

  private final UserService userService;

  /**
   * Returns the extended (v2) profile of the user owning the bearer token.
   *
   * @param principal the authenticated user
   * @return {@code 200 OK} with the v2 profile (v1 fields plus {@code createdAt})
   */
  @Operation(
      summary = "Get the authenticated user's extended profile",
      description = "v2 of /v1/users/me — every v1 field is preserved and createdAt is added. "
          + "Additive evolution: v1 clients keep working unchanged."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Extended profile returned",
          content = @Content(schema = @Schema(implementation = UserResponseV2.class))),
      @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "404", description = "User not found",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @GetMapping("/me")
  public ResponseEntity<UserResponseV2> getCurrentUser(
      @AuthenticationPrincipal SecurityUser principal
  ) {
    return ResponseEntity.ok(userService.getCurrentUserV2(principal.id()));
  }
}
