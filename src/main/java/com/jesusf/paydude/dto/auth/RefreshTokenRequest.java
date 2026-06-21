package com.jesusf.paydude.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Body of {@code POST /v1/auth/refresh}. The presented refresh token is validated, rotated and
 * exchanged for a new access + refresh pair.
 *
 * @param refreshToken raw (unhashed) refresh token previously issued to this client
 */
@Schema(description = "Body for token refresh: the refresh token to validate and rotate.")
public record RefreshTokenRequest(

    @Schema(description = "Raw (unhashed) refresh token previously issued to this client.",
        example = "v4.public.eyJ1c2VyIjoxfQ-OPAQUE-REFRESH-TOKEN",
        requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank String refreshToken
) {
}
