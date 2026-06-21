package com.jesusf.paydude.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

/**
 * Returned by {@code POST /v1/users/me/mfa/confirm}: the single-use recovery codes for the
 * lost-device path. <b>Shown exactly once</b> — only their SHA-256 digests are persisted, so the
 * server cannot re-display them. A client should prompt the user to store them before navigating
 * away.
 *
 * @param recoveryCodes the plaintext codes, never retrievable again
 */
@Schema(description = "Single-use recovery codes, displayed exactly once. Each can replace a "
    + "TOTP code at /v1/auth/mfa/verify if the authenticator device is lost.")
public record MfaRecoveryCodesResponse(

    @Schema(description = "The recovery codes. Store them offline; the server keeps only hashes.",
        example = "[\"K7QW-2MNB-X4ZC\", \"P3RT-9LKJ-D6VS\"]",
        requiredMode = Schema.RequiredMode.REQUIRED)
    List<String> recoveryCodes
) {
}
