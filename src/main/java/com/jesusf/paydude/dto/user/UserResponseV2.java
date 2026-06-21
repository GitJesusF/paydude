package com.jesusf.paydude.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

/**
 * Version 2 read model of a user's profile, returned by the {@code /v2} variant of
 * {@code GET /users/me}.
 *
 * <p>Identical to {@link UserResponse} but adds {@code createdAt}. The separate record — rather
 * than an added field on v1 — is what lets the URI-versioned API evolve the contract without
 * breaking existing v1 clients.
 *
 * @param id        the user id
 * @param firstName the user's given name
 * @param lastName  the user's family name
 * @param email     the account email
 * @param role      the user's {@code Role}, as a string
 * @param status    the user's {@code UserStatus}, as a string
 * @param createdAt when the user account was registered
 */
@Schema(description = "A user's profile (v2) — every v1 field plus the registration timestamp.")
public record UserResponseV2(

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
    String status,

    @Schema(description = "When the user account was registered (UTC).",
        example = "2026-01-15T09:30:00Z", requiredMode = Schema.RequiredMode.REQUIRED)
    Instant createdAt
) {
}
