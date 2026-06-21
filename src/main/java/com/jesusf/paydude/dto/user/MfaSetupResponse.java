package com.jesusf.paydude.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Returned by {@code POST /v1/users/me/mfa/setup}: the provisioning material the client feeds to
 * an authenticator app. Enrollment is <b>pending</b> until {@code /confirm} receives a valid code
 * computed from this secret — handing out the secret enables nothing by itself.
 *
 * <p>This is the only time the secret leaves the server in any form; treat the response as
 * sensitive (render the QR, then drop it).
 *
 * @param secret     the shared secret, Base32 (RFC 4648) — for manual entry when QR is unavailable
 * @param otpauthUri the {@code otpauth://totp/...} Key-Uri the client renders as a QR code
 */
@Schema(description = "TOTP provisioning material. Scan the otpauthUri as a QR (or type the "
    + "Base32 secret), then POST a generated code to /v1/users/me/mfa/confirm.")
public record MfaSetupResponse(

    @Schema(description = "Base32-encoded shared secret for manual entry.",
        example = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", requiredMode = Schema.RequiredMode.REQUIRED)
    String secret,

    @Schema(description = "otpauth:// provisioning URI to render as a QR code.",
        example = "otpauth://totp/PayDude:maria.garcia%40example.com?secret=JBSWY3DPEHPK3PXP"
            + "&issuer=PayDude&algorithm=SHA1&digits=6&period=30",
        requiredMode = Schema.RequiredMode.REQUIRED)
    String otpauthUri
) {
}
