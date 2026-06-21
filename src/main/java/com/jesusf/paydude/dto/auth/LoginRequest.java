package com.jesusf.paydude.dto.auth;

import com.jesusf.paydude.util.EmailNormalizer;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Body of {@code POST /v1/auth/login} — the credentials exchanged for an
 * {@link AuthResponse} token pair.
 *
 * <p>Validation here is deliberately minimal ({@code @NotBlank} only, no format
 * or length rules): the credentials are checked against the stored hash, and
 * echoing a registration-style constraint back to an unauthenticated caller
 * would leak the password policy.
 *
 * @param email    the account email; matched case-insensitively
 * @param password the raw password, verified against the stored BCrypt hash
 */
@Schema(description = "Credentials submitted to obtain an access + refresh token pair.")
public record LoginRequest(

    @Schema(description = "Account email address.", example = "maria.garcia@example.com",
        requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank String email,

    @Schema(description = "Account password, in plain text.", example = "S3cureP@ssphrase!",
        requiredMode = Schema.RequiredMode.REQUIRED, format = "password")
    @NotBlank String password
) {
  public LoginRequest {
    email = EmailNormalizer.normalize(email);
  }
}
