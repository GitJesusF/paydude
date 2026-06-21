package com.jesusf.paydude.dto.audit;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

/**
 * Read model of one security-audit row, returned (paginated) by {@code GET /v1/admin/audit-events}.
 *
 * <p>Admin-only. {@code principal} may carry an attempted login email — the forensic point of the
 * trail; passwords, tokens and full account numbers are never recorded.
 *
 * @param id        audit row id
 * @param eventType the kind of event, as a string
 * @param outcome   {@code SUCCESS} or {@code FAILURE}, as a string
 * @param userId    acting/affected user id, or {@code null} when the actor is unknown
 * @param principal identity the action was attempted as (e.g. login email), or {@code null}
 * @param ipAddress client IP of the request, or {@code null}
 * @param userAgent {@code User-Agent} of the request, or {@code null}
 * @param traceId   W3C trace id for log correlation, or {@code null}
 * @param detail    short, non-sensitive context, or {@code null}
 * @param createdAt when the event was recorded
 */
@Schema(description = "An immutable record of a single security-relevant event.")
public record SecurityAuditEventResponse(

    @Schema(description = "Audit row id.", example = "9012",
        requiredMode = Schema.RequiredMode.REQUIRED)
    Long id,

    @Schema(description = "The kind of event.", example = "LOGIN",
        allowableValues = {"LOGIN", "LOGOUT", "REGISTER", "PASSWORD_CHANGE", "ACCOUNT_LOCKED",
            "TOKEN_REUSE_DETECTED"},
        requiredMode = Schema.RequiredMode.REQUIRED)
    String eventType,

    @Schema(description = "The outcome of the event.", example = "FAILURE",
        allowableValues = {"SUCCESS", "FAILURE"}, requiredMode = Schema.RequiredMode.REQUIRED)
    String outcome,

    @Schema(description = "Acting/affected user id; null when the actor is unknown.",
        example = "42", nullable = true)
    Long userId,

    @Schema(description = "Identity the action was attempted as (e.g. login email); never a secret.",
        example = "attacker@example.com", nullable = true)
    String principal,

    @Schema(description = "Client IP of the request.", example = "203.0.113.7", nullable = true)
    String ipAddress,

    @Schema(description = "User-Agent of the request.", example = "curl/8.4.0", nullable = true)
    String userAgent,

    @Schema(description = "W3C trace id, for correlation with application logs.",
        example = "0af7651916cd43dd8448eb211c80319c", nullable = true)
    String traceId,

    @Schema(description = "Short, non-sensitive context.", example = "bad credentials", nullable = true)
    String detail,

    @Schema(description = "When the event was recorded (UTC).", example = "2026-06-08T21:00:00Z",
        requiredMode = Schema.RequiredMode.REQUIRED)
    Instant createdAt
) {
}
