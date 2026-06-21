package com.jesusf.paydude.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of {@code POST /v1/auth/mfa/verify} — completes a step-up login by pairing the challenge
 * token from {@link MfaChallengeResponse} with proof of the second factor.
 *
 * <p>{@code code} accepts either form of that proof: a 6-digit TOTP from the authenticator app,
 * or one of the single-use recovery codes issued at enrollment (the lost-device path). The server
 * distinguishes them by shape, so the client needs no separate field or endpoint. Validation is
 * deliberately shape-only ({@code @Size} as a parse bound) — which inputs are <i>wrong</i> is the
 * service's call, and both wrong kinds must produce the same 401.
 *
 * @param mfaToken the challenge token returned by {@code /v1/auth/login}
 * @param code     a 6-digit TOTP or a recovery code
 */
@Schema(description = "Completes an MFA login: the challenge token from /v1/auth/login plus a "
    + "6-digit TOTP code or a single-use recovery code.")
public record MfaVerifyRequest(

    @Schema(description = "The mfaToken from the login step-up response.",
        example = "eyJ0eXAiOiJtZmErand0In0.eyJzdWIiOiI0MiJ9.S1gnatuRe",
        requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank String mfaToken,

    @Schema(description = "6-digit TOTP code, or a recovery code (dashes optional).",
        example = "492039", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank @Size(max = 32, message = "Code must not exceed 32 characters")
    String code
) {
}
