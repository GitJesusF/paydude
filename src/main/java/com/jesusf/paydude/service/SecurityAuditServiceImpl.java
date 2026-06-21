package com.jesusf.paydude.service;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.dto.audit.SecurityAuditEventResponse;
import com.jesusf.paydude.entity.SecurityAuditEvent;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.mapper.SecurityAuditEventMapper;
import com.jesusf.paydude.repository.SecurityAuditEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Default {@link SecurityAuditService} implementation.
 *
 * <p>The durability ({@code REQUIRES_NEW}) and fail-safe (swallow write errors) requirements are
 * split across the transactional-proxy boundary: the actual INSERT lives in {@link SecurityAuditWriter}
 * (its own {@code REQUIRES_NEW} transaction), and the fail-safe {@code try/catch} wraps the call to it
 * here — see {@link SecurityAuditWriter} for why that split is mandatory.
 *
 * <p>The class is {@code @Transactional(readOnly = true)}; {@code purgeExpired} overrides that with a
 * writable, rollback-on-any-exception transaction. {@code record} does no DB work directly (it
 * delegates to the writer's own transaction), so it stays read-only.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class SecurityAuditServiceImpl implements SecurityAuditService {

  // Column widths from V0_003 — defensively truncate so an oversized value (a crafted User-Agent, a
  // long attempted email) can never fail the audit INSERT and lose the event.
  private static final int MAX_PRINCIPAL = 255;
  private static final int MAX_IP = 45;
  private static final int MAX_USER_AGENT = 255;
  private static final int MAX_DETAIL = 255;

  private final SecurityAuditEventRepository repository;
  private final SecurityAuditEventMapper mapper;
  private final SecurityAuditWriter writer;
  private final AuditContextResolver contextResolver;
  private final SecurityProperties securityProperties;

  @Override
  public void record(SecurityAuditEventType type, SecurityAuditOutcome outcome,
                     Long userId, String principal, String detail) {
    if (!securityProperties.audit().enabled()) {
      return;
    }

    SecurityAuditEvent event = SecurityAuditEvent.builder()
        .eventType(type)
        .outcome(outcome)
        .userId(userId)
        .principal(truncate(principal, MAX_PRINCIPAL))
        .ipAddress(truncate(contextResolver.currentIp(), MAX_IP))
        .userAgent(truncate(contextResolver.currentUserAgent(), MAX_USER_AGENT))
        .traceId(contextResolver.currentTraceId())
        .detail(truncate(detail, MAX_DETAIL))
        .build();

    // Fail-safe boundary. The writer commits the row in its own REQUIRES_NEW transaction so it
    // survives a rolled-back login; if that write (or its commit) fails, we swallow it with an ERROR
    // log rather than let a broken audit insert disrupt the operation being audited — the same
    // fail-open spirit as the breached-password check.
    try {
      writer.write(event);
    } catch (RuntimeException e) {
      log.error("Failed to record security audit event {}/{} (userId={}) — operation continues",
          type, outcome, userId, e);
    }
  }

  @Override
  public Page<SecurityAuditEventResponse> findEvents(Long userId, SecurityAuditEventType eventType,
                                                     SecurityAuditOutcome outcome, Pageable pageable) {
    return repository.search(userId, eventType, outcome, pageable).map(mapper::toResponse);
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public int purgeExpired() {
    Instant cutoff = Instant.now().minus(securityProperties.audit().retention());
    int purged = repository.deleteByCreatedAtBefore(cutoff);
    if (purged > 0) {
      log.info("Security audit retention purge removed {} event(s) older than {}", purged, cutoff);
    }
    return purged;
  }

  private static String truncate(String value, int maxLength) {
    if (value == null) {
      return null;
    }
    return value.length() <= maxLength ? value : value.substring(0, maxLength);
  }
}
