package com.jesusf.paydude.service;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Resolves the request context (client IP, User-Agent, W3C trace id) for a security audit row from
 * the current thread.
 *
 * <p>This keeps the {@link SecurityAuditService} call sites clean: they pass only the semantic fields
 * (event type, outcome, who) and never have to thread HTTP details down through internal services —
 * {@code LoginAttemptService} and {@code RefreshTokenServiceImpl} emit audit events but otherwise have
 * no reason to touch the web tier. Resolving here, behind an injectable seam, also keeps
 * {@code SecurityAuditServiceImpl} unit-testable (the resolver is mocked) without standing up a
 * servlet request.
 *
 * <p>IP comes from {@code getRemoteAddr()} — the same source the controllers and
 * {@code IpRateLimitFilter} use, which in prod is the real client IP unwrapped by Tomcat's
 * {@code RemoteIpValve} (never raw {@code X-Forwarded-For}). Every getter returns {@code null} outside
 * a servlet request (e.g. a scheduled job), which is harmless: the columns are nullable.
 */
@Component
public class AuditContextResolver {

  private static final String USER_AGENT_HEADER = "User-Agent";
  // The MDC key Spring Boot's micrometer-tracing bridge populates per request (the same key the
  // logback-spring.xml pattern reads). Copying it onto the audit row links the row to the request's logs.
  private static final String TRACE_ID_MDC_KEY = "traceId";

  /** Client IP of the current request, or {@code null} if there is no servlet request. */
  public String currentIp() {
    HttpServletRequest request = currentRequest();
    return request == null ? null : request.getRemoteAddr();
  }

  /** {@code User-Agent} header of the current request, or {@code null}. */
  public String currentUserAgent() {
    HttpServletRequest request = currentRequest();
    return request == null ? null : request.getHeader(USER_AGENT_HEADER);
  }

  /** W3C trace id for the current request, read from the SLF4J MDC, or {@code null}. */
  public String currentTraceId() {
    return MDC.get(TRACE_ID_MDC_KEY);
  }

  private static HttpServletRequest currentRequest() {
    if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
      return attrs.getRequest();
    }
    return null;
  }
}
