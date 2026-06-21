package com.jesusf.paydude.controller;

import com.jesusf.paydude.dto.audit.SecurityAuditEventResponse;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.security.CustomUserDetailsService;
import com.jesusf.paydude.security.JwtService;
import com.jesusf.paydude.security.ratelimit.AuthRateLimiter;
import com.jesusf.paydude.service.SecurityAuditService;
import com.jesusf.paydude.support.WithMockSecurityUser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web-layer tests for {@link AdminAuditController}.
 *
 * <p>The JWT filter chain is disabled at slice level ({@code addFilters = false}), so the
 * {@code ROLE_ADMIN} authorization itself (a {@code 403} for a normal user) is <b>not</b> exercised
 * here — that is enforced by {@code SecurityConfig}'s URL matcher and proven end-to-end in
 * {@code SecurityAuditIT}. What this slice pins is the controller contract: the optional query
 * filters bind to their typed values and forward to the service, and the {@code Page} comes back
 * wrapped in the stable {@link com.jesusf.paydude.dto.PagedResponse} envelope (never a raw
 * {@code PageImpl}).
 */
@WebMvcTest(controllers = AdminAuditController.class)
@AutoConfigureMockMvc(addFilters = false)
class AdminAuditControllerTest {

  @Autowired private MockMvc mockMvc;

  @MockitoBean private SecurityAuditService securityAuditService;
  // SecurityConfig requires these two beans to build the context, even with addFilters=false.
  @MockitoBean private JwtService jwtService;
  @MockitoBean private CustomUserDetailsService userDetailsService;
  // The slice scans IpRateLimitFilter (@Component), which needs AuthRateLimiter at construction —
  // addFilters=false stops it from running, not from being created.
  @MockitoBean private AuthRateLimiter authRateLimiter;

  @Test
  @DisplayName("GET /admin/audit-events - returns 200 with the PagedResponse envelope")
  @WithMockSecurityUser(role = "ROLE_ADMIN")
  void returnsPagedEnvelope() throws Exception {
    SecurityAuditEventResponse row = new SecurityAuditEventResponse(
        9012L, "LOGIN", "FAILURE", null, "attacker@example.com", "203.0.113.7", "curl/8.4.0",
        "0af7651916cd43dd8448eb211c80319c", "bad credentials", Instant.parse("2026-06-08T21:00:00Z"));
    Page<SecurityAuditEventResponse> page = new PageImpl<>(List.of(row), PageRequest.of(0, 20), 1);
    when(securityAuditService.findEvents(any(), any(), any(), any())).thenReturn(page);

    mockMvc.perform(get("/v1/admin/audit-events"))
        .andExpect(status().isOk())
        // PagedResponse envelope (not a leaked PageImpl): its six fixed fields plus the mapped row.
        .andExpect(jsonPath("$.content[0].id").value(9012))
        .andExpect(jsonPath("$.content[0].eventType").value("LOGIN"))
        .andExpect(jsonPath("$.content[0].outcome").value("FAILURE"))
        .andExpect(jsonPath("$.content[0].principal").value("attacker@example.com"))
        .andExpect(jsonPath("$.page").value(0))
        .andExpect(jsonPath("$.size").value(20))
        .andExpect(jsonPath("$.totalElements").value(1))
        .andExpect(jsonPath("$.totalPages").value(1))
        .andExpect(jsonPath("$.hasNext").value(false));
  }

  @Test
  @DisplayName("GET /admin/audit-events - parses and forwards the optional filters as typed values")
  @WithMockSecurityUser(role = "ROLE_ADMIN")
  void forwardsFilters() throws Exception {
    when(securityAuditService.findEvents(any(), any(), any(), any()))
        .thenReturn(new PageImpl<>(List.of(), PageRequest.of(0, 20), 0));

    mockMvc.perform(get("/v1/admin/audit-events")
            .param("userId", "42")
            .param("eventType", "LOGIN")
            .param("outcome", "FAILURE"))
        .andExpect(status().isOk());

    // The query params bind to their types (Long + the two enums) and forward to the service.
    verify(securityAuditService).findEvents(
        eq(42L), eq(SecurityAuditEventType.LOGIN), eq(SecurityAuditOutcome.FAILURE), any(Pageable.class));
  }

  @Test
  @DisplayName("GET /admin/audit-events - with no filters forwards nulls (unfiltered view)")
  @WithMockSecurityUser(role = "ROLE_ADMIN")
  void noFiltersForwardsNulls() throws Exception {
    when(securityAuditService.findEvents(any(), any(), any(), any()))
        .thenReturn(new PageImpl<>(List.of(), PageRequest.of(0, 20), 0));

    mockMvc.perform(get("/v1/admin/audit-events"))
        .andExpect(status().isOk());

    verify(securityAuditService).findEvents(isNull(), isNull(), isNull(), any(Pageable.class));
  }
}
