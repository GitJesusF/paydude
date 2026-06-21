package com.jesusf.paydude.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Read model of a user's profile, returned by {@code GET /v1/users/me} (v1).
 *
 * <p>Profile data is served from a dedicated endpoint rather than embedded in the login response
 * or the JWT, keeping tokens free of PII. See {@code UserResponseV2} for the versioned successor
 * that adds {@code createdAt}.
 *
 * @param id        the user id
 * @param firstName the user's given name
 * @param lastName  the user's family name
 * @param email     the account email
 * @param role      the user's {@code Role}, as a string
 * @param status    the user's {@code UserStatus}, as a string
 */
@Schema(description = "A user's profile (v1).")
public record UserResponse(

    @Schema(description = "User id.", example = "1", requiredMode = Schema.RequiredMode.REQUIRED)
    Long id,

    @Schema(description = "User's given name.", example = "Maria",
        requiredMode = Schema.RequiredMode.REQUIRED)
    String firstName,

    @Schema(description = "User's family name.", example = "Garcia",
        requiredMode = Schema.RequiredMode.REQUIRED)
    String lastName,

    @Schema(description = "Account email address.", example = "maria.garcia@example.com",
        requiredMode = Schema.RequiredMode.REQUIRED)
    String email,

    @Schema(description = "Authorization role.", example = "ROLE_USER",
        allowableValues = {"ROLE_USER", "ROLE_ADMIN"}, requiredMode = Schema.RequiredMode.REQUIRED)
    String role,

    @Schema(description = "Account lifecycle status.", example = "ACTIVE",
        allowableValues = {"ACTIVE", "LOCKED", "SUSPENDED", "CLOSED"},
        requiredMode = Schema.RequiredMode.REQUIRED)
    String status
) {
}
