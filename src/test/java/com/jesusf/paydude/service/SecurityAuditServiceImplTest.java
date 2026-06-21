package com.jesusf.paydude.service;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.config.properties.SecurityProperties.Audit;
import com.jesusf.paydude.dto.audit.SecurityAuditEventResponse;
import com.jesusf.paydude.entity.SecurityAuditEvent;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.mapper.SecurityAuditEventMapper;
import com.jesusf.paydude.repository.SecurityAuditEventRepository;
import com.jesusf.paydude.support.SecurityPropertiesFixture;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SecurityAuditServiceImpl}.
 *
 * <p>The durability of the write (REQUIRES_NEW, surviving a rolled-back login) is an
 * integration-level property proven by {@code SecurityAuditIT} against Postgres — it cannot be shown
 * against a mocked writer. What these tests pin is the in-process behaviour the service owns: the row
 * is built from the semantic fields plus the request context the resolver supplies, the enabled
 * toggle short-circuits, recording is <b>fail-safe</b> (a writer failure is swallowed, never
 * propagated), oversized values are truncated to the column widths, reads delegate to the repository
 * and map, and the retention purge computes a {@code now − retention} cutoff.
 */
@ExtendWith(MockitoExtension.class)
class SecurityAuditServiceImplTest {

  @Mock private SecurityAuditEventRepository repository;
  @Mock private SecurityAuditEventMapper mapper;
  @Mock private SecurityAuditWriter writer;
  @Mock private AuditContextResolver contextResolver;

  private SecurityAuditServiceImpl serviceWith(Audit audit) {
    SecurityProperties properties = SecurityPropertiesFixture.withAudit(audit);
    return new SecurityAuditServiceImpl(repository, mapper, writer, contextResolver, properties);
  }

  private SecurityAuditServiceImpl enabledService() {
    return serviceWith(new Audit(true, Duration.ofDays(365)));
  }

  @Nested
  @DisplayName("record")
  class Record {

    @Test
    @DisplayName("builds the row from the semantic fields plus resolved request context, then writes it")
    void buildsRowAndWrites() {
      when(contextResolver.currentIp()).thenReturn("203.0.113.7");
      when(contextResolver.currentUserAgent()).thenReturn("curl/8.4.0");
      when(contextResolver.currentTraceId()).thenReturn("0af7651916cd43dd8448eb211c80319c");

      enabledService().record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE,
          null, "attacker@example.com", "bad credentials");

      ArgumentCaptor<SecurityAuditEvent> captor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
      verify(writer).write(captor.capture());
      SecurityAuditEvent row = captor.getValue();
      assertEquals(SecurityAuditEventType.LOGIN, row.getEventType());
      assertEquals(SecurityAuditOutcome.FAILURE, row.getOutcome());
      assertNull(row.getUserId(), "userId is null for a failed login on an unrecognised email");
      assertEquals("attacker@example.com", row.getPrincipal());
      assertEquals("203.0.113.7", row.getIpAddress());
      assertEquals("curl/8.4.0", row.getUserAgent());
      assertEquals("0af7651916cd43dd8448eb211c80319c", row.getTraceId());
      assertEquals("bad credentials", row.getDetail());
    }

    @Test
    @DisplayName("is a no-op (no context resolution, no write) when auditing is disabled")
    void noOpWhenDisabled() {
      serviceWith(new Audit(false, Duration.ofDays(365)))
          .record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.SUCCESS, 1L, "u@test.com", null);

      verifyNoInteractions(writer, contextResolver, repository);
    }

    @Test
    @DisplayName("is fail-safe: a write failure is swallowed, never propagated to the audited operation")
    void failSafeWhenWriteThrows() {
      // An audit failure must never break the audited operation: record(...) swallows the
      // exception (logging ERROR) instead of propagating it.
      doThrow(new RuntimeException("DB down")).when(writer).write(any());

      assertDoesNotThrow(() -> enabledService().record(
          SecurityAuditEventType.LOGIN, SecurityAuditOutcome.SUCCESS, 1L, "u@test.com", null));
    }

    @Test
    @DisplayName("truncates an over-long principal to the column width so the INSERT never fails")
    void truncatesOverlongPrincipal() {
      enabledService().record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE,
          null, "x".repeat(300), null);

      ArgumentCaptor<SecurityAuditEvent> captor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
      verify(writer).write(captor.capture());
      assertEquals(255, captor.getValue().getPrincipal().length(),
          "principal must be truncated to the column width (255)");
    }

    @Test
    @DisplayName("truncates over-long user-agent and detail to their column widths")
    void truncatesOverlongUserAgentAndDetail() {
      // A crafted User-Agent header is attacker-controlled input; an oversized value must be
      // clipped, never allowed to fail the INSERT and silence the audit row.
      when(contextResolver.currentUserAgent()).thenReturn("u".repeat(300));

      enabledService().record(SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE,
          null, "a@test.com", "d".repeat(300));

      ArgumentCaptor<SecurityAuditEvent> captor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
      verify(writer).write(captor.capture());
      assertEquals(255, captor.getValue().getUserAgent().length(),
          "user_agent must be truncated to the column width (255)");
      assertEquals(255, captor.getValue().getDetail().length(),
          "detail must be truncated to the column width (255)");
    }
  }

  @Nested
  @DisplayName("findEvents")
  class FindEvents {

    @Test
    @DisplayName("delegates to the repository search and maps each row to its response DTO")
    void delegatesAndMaps() {
      Pageable pageable = PageRequest.of(0, 20);
      SecurityAuditEvent entity = SecurityAuditEvent.builder().id(7L).build();
      SecurityAuditEventResponse dto = new SecurityAuditEventResponse(
          7L, "LOGIN", "FAILURE", null, "a@test.com", null, null, null, "bad credentials", Instant.now());
      when(repository.search(null, SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE, pageable))
          .thenReturn(new PageImpl<>(List.of(entity), pageable, 1));
      when(mapper.toResponse(entity)).thenReturn(dto);

      Page<SecurityAuditEventResponse> result = enabledService().findEvents(
          null, SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE, pageable);

      assertEquals(1, result.getTotalElements());
      assertEquals(dto, result.getContent().get(0));
      verify(repository).search(null, SecurityAuditEventType.LOGIN, SecurityAuditOutcome.FAILURE, pageable);
    }
  }

  @Nested
  @DisplayName("purgeExpired")
  class PurgeExpired {

    @Test
    @DisplayName("deletes rows older than now minus the configured retention and returns the count")
    void deletesByRetentionCutoff() {
      Duration retention = Duration.ofDays(30);
      when(repository.deleteByCreatedAtBefore(any())).thenReturn(11);

      Instant lowerBound = Instant.now().minus(retention);
      int purged = serviceWith(new Audit(true, retention)).purgeExpired();
      Instant upperBound = Instant.now().minus(retention);

      assertEquals(11, purged, "the count must be propagated from the repository verbatim");
      ArgumentCaptor<Instant> cutoff = ArgumentCaptor.forClass(Instant.class);
      verify(repository).deleteByCreatedAtBefore(cutoff.capture());
      assertFalse(cutoff.getValue().isBefore(lowerBound), "cutoff must be >= now - retention");
      assertFalse(cutoff.getValue().isAfter(upperBound), "cutoff must be <= now - retention");
    }
  }
}
