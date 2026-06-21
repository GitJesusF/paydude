package com.jesusf.paydude.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Body of {@code POST /v1/users/me/mfa/confirm} — proves the authenticator actually produces
 * valid codes for the pending secret before MFA is switched on. Without this round-trip, a typo'd
 * manual entry or a failed QR scan would arm a second factor the user can never satisfy:
 * self-inflicted account lockout at the very next login.
 *
 * @param code a 6-digit TOTP computed from the secret issued at {@code /setup}
 */
@Schema(description = "Activates TOTP: a current 6-digit code generated from the secret issued "
    + "at /v1/users/me/mfa/setup.")
public record MfaConfirmRequest(

    @Schema(description = "Current 6-digit TOTP code.", example = "492039",
        requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Code required")
    @Pattern(regexp = "\\d{6}", message = "Code must be exactly 6 digits")
    String code
) {
}
