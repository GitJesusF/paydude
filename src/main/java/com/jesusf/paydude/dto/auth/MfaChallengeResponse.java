package com.jesusf.paydude.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Returned by {@code POST /v1/auth/login} <i>instead of</i> an {@link AuthResponse} when the
 * account has the TOTP second factor enabled: the password stage passed, but no session exists
 * yet. The client must present {@code mfaToken} together with a TOTP or recovery code at
 * {@code POST /v1/auth/mfa/verify} to complete the login and receive the token pair.
 *
 * <p>{@code mfaRequired} is the body-level discriminator between the two possible 200 shapes of
 * the login endpoint — always {@code true} here, absent from {@code AuthResponse} — so clients
 * branch on one stable field rather than sniffing for {@code accessToken}.
 *
 * @param mfaRequired always {@code true}; discriminates this shape from {@link AuthResponse}
 * @param mfaToken    short-lived, signed challenge token ({@code typ: mfa+jwt}) proving the
 *                    password stage; consumable only at {@code /v1/auth/mfa/verify}
 * @param expiresIn   challenge lifetime in seconds, derived from
 *                    {@code application.security.mfa.challenge-expiration}
 */
@Schema(description = "Login step-up response: the password was correct but the account requires "
    + "a TOTP second factor. POST the mfaToken plus a code to /v1/auth/mfa/verify to obtain the "
    + "token pair.")
public record MfaChallengeResponse(

    @Schema(description = "Always true — discriminates this shape from the AuthResponse the same "
        + "endpoint returns for single-factor accounts.",
        example = "true", requiredMode = Schema.RequiredMode.REQUIRED)
    boolean mfaRequired,

    @Schema(description = "One-shot MFA challenge token. Send it in the body of "
        + "/v1/auth/mfa/verify together with a 6-digit TOTP or a recovery code.",
        example = "eyJ0eXAiOiJtZmErand0In0.eyJzdWIiOiI0MiJ9.S1gnatuRe",
        requiredMode = Schema.RequiredMode.REQUIRED)
    String mfaToken,

    @Schema(description = "Challenge lifetime in seconds.", example = "300",
        requiredMode = Schema.RequiredMode.REQUIRED)
    long expiresIn
) {
}
