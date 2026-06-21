package com.jesusf.paydude.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * OAuth 2.0-style token response (RFC 6749 §5.1).
 *
 * <p>Intentionally <b>does not</b> carry user profile data (firstName, email, etc.). Profile
 * lookups belong on a separate endpoint (e.g. {@code /users/me}) so that:
 * <ul>
 *   <li>The login path stays free of any DB read beyond the one that {@code DaoAuthenticationProvider}
 *       already performs to verify the password.</li>
 *   <li>JWTs do not need to carry PII — claims stay strictly authorization data
 *       (id, role, status, expirations).</li>
 *   <li>Token issuance and profile retrieval can evolve independently.</li>
 * </ul>
 *
 * <p>The same record is returned by {@code /v1/auth/login}, {@code /v1/auth/register} and
 * {@code /v1/auth/refresh}. The shape matches OAuth 2.0's documented response so existing
 * client SDKs work out of the box.
 *
 * @param accessToken       the signed JWT
 * @param tokenType         always {@code "Bearer"} in this API. Kept as a field (rather than implicit)
 *                          to keep the response self-describing for OAuth-aware clients
 * @param expiresIn         access-token lifetime in seconds, derived from
 *                          {@code application.security.jwt.expiration}. Lets the client schedule a
 *                          refresh without parsing the JWT body
 * @param refreshToken      opaque single-use refresh token. To obtain a new access token, the client
 *                          posts this value to {@code /v1/auth/refresh}; the value is then rotated
 *                          and the old one becomes invalid. Used out-of-band (a leaked one triggers
 *                          family-wide revocation on next use — see {@code RefreshTokenServiceImpl})
 * @param refreshExpiresIn  refresh-token lifetime in seconds, derived from
 *                          {@code application.security.refresh-token.expiration}. After this window
 *                          the user must re-login via {@code /v1/auth/login}
 */
@Schema(description = "OAuth 2.0-style token response (RFC 6749 §5.1). Returned by login, "
    + "register and refresh. Carries no user profile data — fetch that from /v1/users/me.")
public record AuthResponse(

    @Schema(description = "The signed JWT access token. Send it as 'Authorization: Bearer <token>'.",
        example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtYXJpYUBleGFtcGxlLmNvbSJ9.S1gnatuRe",
        requiredMode = Schema.RequiredMode.REQUIRED)
    String accessToken,

    @Schema(description = "Token type — always 'Bearer'.", example = "Bearer",
        requiredMode = Schema.RequiredMode.REQUIRED)
    String tokenType,

    @Schema(description = "Access-token lifetime in seconds.", example = "900",
        requiredMode = Schema.RequiredMode.REQUIRED)
    long expiresIn,

    @Schema(description = "Opaque single-use refresh token. POST it to /v1/auth/refresh to rotate.",
        example = "v4.public.eyJ1c2VyIjoxfQ-OPAQUE-REFRESH-TOKEN",
        requiredMode = Schema.RequiredMode.REQUIRED)
    String refreshToken,

    @Schema(description = "Refresh-token lifetime in seconds.", example = "604800",
        requiredMode = Schema.RequiredMode.REQUIRED)
    long refreshExpiresIn
) {
}
