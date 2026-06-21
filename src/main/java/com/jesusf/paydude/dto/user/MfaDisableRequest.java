package com.jesusf.paydude.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Body of {@code POST /v1/users/me/mfa/disable}.
 *
 * <p>Same re-authentication rule as {@link MfaSetupRequest}, inverted threat: with only a stolen
 * access token, disabling MFA would strip the account back to single-factor — exactly the
 * downgrade the second factor exists to prevent. The password gate keeps that decision with the
 * account owner.
 *
 * @param password the account password, verified before MFA is turned off
 */
@Schema(description = "Disables TOTP. Requires the account password — a bearer token alone must "
    + "not be able to downgrade the account to single-factor.")
public record MfaDisableRequest(

    @Schema(description = "The account password, re-verified before MFA is disabled.",
        example = "S3cureP@ssphrase!", requiredMode = Schema.RequiredMode.REQUIRED,
        format = "password")
    @NotBlank(message = "Password required")
    String password
) {
}
