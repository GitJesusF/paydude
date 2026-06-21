package com.jesusf.paydude.dto.auth;

import com.jesusf.paydude.util.EmailNormalizer;
import com.jesusf.paydude.validation.MaxByteLength;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of {@code POST /v1/auth/register}.
 *
 * <p>The password rule — 8 to 64 characters, no composition requirements —
 * follows NIST SP 800-63B §5.1.1.2. Length is the only structural constraint,
 * plus a 72-byte (UTF-8) ceiling so a long non-ASCII passphrase cannot be
 * silently truncated by BCrypt. Breach screening against the HaveIBeenPwned
 * corpus happens in the service layer rather than as a bean-validation annotation.
 *
 * @param firstName the user's given name
 * @param lastName  the user's family name
 * @param email     a well-formed email address; must be unique
 * @param password  the raw password, hashed with BCrypt before persistence
 */
@Schema(description = "Registration details for a new user account.")
public record RegisterRequest(

    @Schema(description = "User's given name.", example = "Maria",
        requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "First name required")
    String firstName,

    @Schema(description = "User's family name.", example = "Garcia",
        requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Last name required")
    String lastName,

    @Schema(description = "A well-formed, unique email address.", example = "maria.garcia@example.com",
        requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Email required")
    @Email(message = "Invalid email format")
    String email,

    @Schema(description = "Password between 8 and 64 characters, at most 72 bytes UTF-8 "
        + "(NIST SP 800-63B). Rejected if it appears in the HaveIBeenPwned breach corpus.",
        example = "S3cureP@ssphrase!", minLength = 8, maxLength = 64,
        requiredMode = Schema.RequiredMode.REQUIRED, format = "password")
    @NotBlank(message = "Password required")
    @Size(min = 8, max = 64, message = "Password must be between 8 and 64 characters")
    @MaxByteLength(value = 72, message = "Password must not exceed 72 bytes when UTF-8 encoded")
    String password
) {
  public RegisterRequest {
    email = EmailNormalizer.normalize(email);
  }
}
