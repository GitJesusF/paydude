package com.jesusf.paydude.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Body of {@code POST /v1/users/me/mfa/setup}.
 *
 * <p>The password is required even though the caller already holds a valid access token — the
 * same re-authentication rule as {@link ChangePasswordRequest} (OWASP ASVS v4 §2.4.5), and for a
 * sharper reason here: with only the token, a thief could enroll <b>their own</b> authenticator
 * on the victim's account, locking the legitimate owner out of every future login. MFA
 * enrollment is precisely the kind of account takeover a stolen token must not be able to commit.
 *
 * @param password the account password, verified before a secret is generated
 */
@Schema(description = "Starts TOTP enrollment. Requires the account password — a bearer token "
    + "alone must not be able to enroll a new authenticator.")
public record MfaSetupRequest(

    @Schema(description = "The account password, re-verified before enrollment begins.",
        example = "S3cureP@ssphrase!", requiredMode = Schema.RequiredMode.REQUIRED,
        format = "password")
    @NotBlank(message = "Password required")
    String password
) {
}
