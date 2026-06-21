package com.jesusf.paydude.dto.user;

import com.jesusf.paydude.validation.MaxByteLength;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of {@code PATCH /v1/users/me/password}.
 *
 * <p>{@code currentPassword} is mandatory even though the caller already proves identity with
 * their access token. The extra check defends against a stolen access token being used to lock
 * the legitimate owner out by changing the password — a near-universal pattern across financial
 * apps and the explicit recommendation of OWASP ASVS v4 §2.4.5.
 *
 * @param currentPassword Existing password — verified against the BCrypt hash before any change
 * @param newPassword     Replacement. Same length rule as registration ({@code @Size}: 8–64
 *                        characters, plus a 72-byte UTF-8 ceiling for BCrypt, per NIST SP
 *                        800-63B §5.1.1.2), kept aligned on purpose so users do not see one
 *                        constraint at signup and a different one at rotation
 */
@Schema(description = "Body for a password change: the current password and the replacement.")
public record ChangePasswordRequest(

    @Schema(description = "The user's current password, verified before the change is applied.",
        example = "0ldP@ssphrase!", requiredMode = Schema.RequiredMode.REQUIRED, format = "password")
    @NotBlank(message = "Current password required")
    String currentPassword,

    @Schema(description = "The new password — 8 to 64 characters, at most 72 bytes UTF-8, "
        + "screened against the HaveIBeenPwned breach corpus.",
        example = "S3cureP@ssphrase!", minLength = 8, maxLength = 64,
        requiredMode = Schema.RequiredMode.REQUIRED, format = "password")
    @NotBlank(message = "New password required")
    @Size(min = 8, max = 64, message = "Password must be between 8 and 64 characters")
    @MaxByteLength(value = 72, message = "Password must not exceed 72 bytes when UTF-8 encoded")
    String newPassword
) {
}
