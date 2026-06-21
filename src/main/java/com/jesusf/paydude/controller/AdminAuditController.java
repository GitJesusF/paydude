package com.jesusf.paydude.controller;

import com.jesusf.paydude.config.web.ApiV1;
import com.jesusf.paydude.dto.PagedResponse;
import com.jesusf.paydude.dto.audit.SecurityAuditEventResponse;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.service.SecurityAuditService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Admin-only read access to the security audit trail. Mounted under {@code /v1/admin/audit-events}.
 *
 * <p>This is the "protect access to the logs" half of OWASP ASVS V7 — and PayDude's first
 * RBAC-gated API endpoint: {@code SecurityConfig} restricts {@code /v1/admin/**} to
 * {@code ROLE_ADMIN} (until now {@code ROLE_ADMIN} guarded only the Actuator chain). A normal user's
 * valid token therefore gets {@code 403}, rendered as the same RFC 9457 {@code ProblemDetail} as
 * every other error.
 *
 * <p>Results come back in the stable {@link PagedResponse} envelope, newest first. Three optional
 * query filters narrow the view (by user, event type, outcome) and are combined by the service's
 * single nullable-filter query.
 */
@RestController
@RequestMapping("/admin/audit-events")
@ApiV1
@RequiredArgsConstructor
@Tag(name = "Admin · Audit",
    description = "Admin-only access to the security audit trail (OWASP ASVS V7). Requires ROLE_ADMIN.")
@SecurityRequirement(name = "bearerAuth")
public class AdminAuditController {

  private final SecurityAuditService securityAuditService;

  /**
   * Returns a page of the security audit trail, newest first, optionally filtered.
   *
   * @param userId    optional filter by acting/affected user id
   * @param eventType optional filter by event type
   * @param outcome   optional filter by outcome
   * @param pageable  page index, size and sort (defaults: size 20, by {@code createdAt} desc)
   * @return {@code 200 OK} with a {@link PagedResponse} of audit events
   */
  @Operation(
      summary = "List security audit events (admin)",
      description = "Returns a paginated, newest-first view of the security audit trail — login "
          + "success/failure, logout, registration, password change, account lockout and "
          + "refresh-token reuse. Restricted to ROLE_ADMIN. Optional filters: userId, eventType, outcome."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A page of audit events",
          content = @Content(schema = @Schema(implementation = PagedResponse.class))),
      @ApiResponse(responseCode = "401", description = "Missing or invalid access token",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class))),
      @ApiResponse(responseCode = "403", description = "Authenticated but not an administrator",
          content = @Content(mediaType = "application/problem+json",
              schema = @Schema(implementation = ProblemDetail.class)))
  })
  @GetMapping
  public ResponseEntity<PagedResponse<SecurityAuditEventResponse>> list(
      @Parameter(description = "Filter by acting/affected user id")
      @RequestParam(required = false) Long userId,

      @Parameter(description = "Filter by event type")
      @RequestParam(required = false) SecurityAuditEventType eventType,

      @Parameter(description = "Filter by outcome (SUCCESS/FAILURE)")
      @RequestParam(required = false) SecurityAuditOutcome outcome,

      @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable
  ) {
    return ResponseEntity.ok(PagedResponse.from(
        securityAuditService.findEvents(userId, eventType, outcome, pageable)));
  }
}
