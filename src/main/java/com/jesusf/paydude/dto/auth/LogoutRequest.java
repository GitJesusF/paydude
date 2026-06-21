package com.jesusf.paydude.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Body of {@code POST /v1/auth/logout}. Revokes the family of the presented refresh token —
 * all access tokens minted with the same family die alongside it on next request. The endpoint
 * is idempotent: an unknown or already-revoked token is a 204 just the same.
 *
 * @param refreshToken raw refresh token currently held by the client
 */
@Schema(description = "Body for logout: the refresh token whose session family should be revoked.")
public record LogoutRequest(

    @Schema(description = "Raw (unhashed) refresh token currently held by the client.",
        example = "v4.public.eyJ1c2VyIjoxfQ-OPAQUE-REFRESH-TOKEN",
        requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank String refreshToken
) {
}
