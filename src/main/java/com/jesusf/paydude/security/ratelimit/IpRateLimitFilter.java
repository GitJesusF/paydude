package com.jesusf.paydude.security.ratelimit;

import com.jesusf.paydude.exception.RateLimitExceededException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

/**
 * IP-based throttle applied at the earliest servlet filter position — before Spring Security, the
 * dispatcher, and any controller code. Pairs with the email- and account-keyed throttles that stay
 * inside the controller layer: this filter is the infrastructure tier (cheap, coarse, pre-body),
 * the controller calls are the business tier (parsed input, authenticated principal).
 *
 * <p>Two reasons this lives in a filter rather than the controller:
 * <ul>
 *   <li><b>Cost asymmetry.</b> {@code POST /v1/auth/login} performs a BCrypt verification (≈100 ms
 *       of CPU per call). A controller-level throttle still pays the cost of body parsing,
 *       validation, dispatcher resolution, and Spring Security's full chain before the check fires.
 *       Cutting an attacker off at the first filter saves that work — closer in spirit to what a
 *       reverse proxy or WAF would do, executed in-process.</li>
 *   <li><b>Separation of concerns.</b> Per-IP throttles are oblivious to who the caller claims to
 *       be; per-account throttles depend on the parsed email and on knowing whether the auth
 *       succeeded (for {@link AuthRateLimiter#recordSuccessfulLogin}). Keeping the two tiers in
 *       different code paths makes the trust boundaries explicit.</li>
 * </ul>
 *
 * <h2>Client IP — trust model</h2>
 * The IP is read from {@link HttpServletRequest#getRemoteAddr()}, never directly from
 * {@code X-Forwarded-For}. Reading the header in application code is unsafe: any client can send
 * a forged value and trivially evade per-IP limits by rotating fake addresses. In production the
 * deployment sets {@code server.forward-headers-strategy=native} (see
 * {@code application-prod.properties}); Tomcat's {@code RemoteIpValve} then unwraps
 * {@code X-Forwarded-For} <i>only</i> when the immediate TCP peer matches the configured
 * {@code internal-proxies} CIDRs, after which {@code getRemoteAddr()} returns the real client IP.
 * In dev/test, where no proxy sits in front, the same call returns the actual peer with no header
 * processing — also safe.
 *
 * <p>The path match strips {@code request.getContextPath()} before comparing against
 * {@code /v1/auth/*}. Otherwise a deployment mounted under {@code /paydude} would see
 * {@code /paydude/v1/auth/login} and skip the IP throttle entirely.
 *
 * <h2>Filter order</h2>
 * {@code HIGHEST_PRECEDENCE + 10}. Runs after Spring Boot's {@code ServerHttpObservationFilter}
 * ({@code HIGHEST_PRECEDENCE + 1}), which opens the W3C trace context for the request — so the
 * 429 log line already carries the {@code traceId} — and well before Spring Security's
 * {@code FilterChainProxy} (default order {@code -100}).
 *
 * <h2>RateLimit response headers</h2>
 * On every in-scope request — allowed <i>or</i> throttled — the filter emits the IETF
 * {@code RateLimit} / {@code RateLimit-Policy} header fields (see {@link RateLimitHeaders}) for the
 * per-IP bucket guarding that endpoint. Emitting them on the success path (not only on the 429) is
 * the whole point of the standard: a well-behaved SDK reads {@code RateLimit: …;r=2;…} and slows
 * down before it trips the limit. The numbers come entirely from the {@link RateLimitSnapshot} the
 * limiter returns, so the filter needs no extra configuration dependency (it stays light enough to
 * be component-scanned into {@code @WebMvcTest} slices). The headers are written before the request
 * proceeds, so they are present whether the response comes back 2xx from the controller or 429 from
 * this filter. (The authenticated email/user tiers keep their {@code Retry-After}-only 429s;
 * extending proactive {@code RateLimit} headers to them is a mechanical follow-up.)
 *
 * <h2>Error shape</h2>
 * On throttle, the filter forwards a {@link RateLimitExceededException} through
 * {@link HandlerExceptionResolver}. That delegates to {@code RateLimitExceptionHandler}, which
 * returns the canonical {@code application/problem+json} body with the {@code Retry-After} header
 * — the same JSON shape the rest of the API uses. The {@code RateLimit} headers written before the
 * forward survive onto that 429 response. Writing the body directly here would leak a second error
 * format to clients.
 *
 * <h2>Method filtering</h2>
 * Only {@code POST} consumes a token. A {@code GET}/{@code HEAD}/{@code OPTIONS} on the same path
 * is out of scope for brute-force, and counting it would let an attacker DoS legitimate users
 * behind shared NAT just by spamming wrong-method requests.
 */
@RequiredArgsConstructor
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class IpRateLimitFilter extends OncePerRequestFilter {

  private static final String LOGIN_PATH = "/v1/auth/login";
  private static final String REGISTER_PATH = "/v1/auth/register";
  private static final String REFRESH_PATH = "/v1/auth/refresh";
  private static final String MFA_VERIFY_PATH = "/v1/auth/mfa/verify";
  private static final String POST_METHOD = "POST";

  // RateLimit / RateLimit-Policy partition names — the quoted structured-field key that ties the
  // dynamic RateLimit field to its static RateLimit-Policy.
  private static final String LOGIN_POLICY = "login";
  private static final String REGISTER_POLICY = "register";
  private static final String REFRESH_POLICY = "refresh";
  private static final String MFA_POLICY = "mfa";

  // Hints to the client, not the actual bucket period. The underlying refill window is configured
  // via application.security.rate-limit.* and can drift from these values without breaking
  // anything — Retry-After is documented as a "no earlier than" suggestion (RFC 7231 §7.1.3).
  private static final int LOGIN_RETRY_AFTER_SECONDS = 60;
  private static final int REGISTER_RETRY_AFTER_SECONDS = 3600;
  private static final int REFRESH_RETRY_AFTER_SECONDS = 60;
  private static final int MFA_RETRY_AFTER_SECONDS = 60;

  private final AuthRateLimiter rateLimiter;
  @Qualifier("handlerExceptionResolver")
  private final HandlerExceptionResolver resolver;

  /**
   * Applies the per-IP throttle: writes the {@code RateLimit} headers for the matched bucket and, if
   * the request exceeds it, forwards the exception to the MVC resolver and terminates the chain;
   * otherwise the request proceeds normally.
   */
  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain
  ) throws ServletException, IOException {

    try {
      applyIpRateLimit(request, response);
    } catch (RateLimitExceededException violation) {
      // Same delegation pattern as JwtAuthenticationFilter: hand the exception to the MVC resolver
      // so RateLimitExceptionHandler builds the ProblemDetail + Retry-After. The RateLimit headers
      // set just above survive onto the 429. No chain.doFilter — the request ends here.
      resolver.resolveException(request, response, null, violation);
      return;
    }

    filterChain.doFilter(request, response);
  }

  /**
   * Consumes one token from the per-IP bucket guarding the requested endpoint, writes the
   * {@code RateLimit} headers from the result, and raises {@link RateLimitExceededException} when the
   * bucket is exhausted. A non-{@code POST} verb, or a path outside the throttle's scope, returns
   * without touching a bucket or writing headers so the chain proceeds untouched.
   */
  private void applyIpRateLimit(HttpServletRequest request, HttpServletResponse response) {
    if (!POST_METHOD.equals(request.getMethod())) {
      return;
    }

    final String ip = request.getRemoteAddr();
    switch (requestPath(request)) {
      case LOGIN_PATH -> enforce(response, LOGIN_POLICY, rateLimiter.checkLoginByIp(ip),
          "Too many login attempts from this IP. Try again later.", LOGIN_RETRY_AFTER_SECONDS);
      case REGISTER_PATH -> enforce(response, REGISTER_POLICY, rateLimiter.checkRegisterByIp(ip),
          "Too many registration attempts from this IP. Try again later.", REGISTER_RETRY_AFTER_SECONDS);
      case REFRESH_PATH -> enforce(response, REFRESH_POLICY, rateLimiter.checkRefreshByIp(ip),
          "Too many refresh attempts from this IP. Try again later.", REFRESH_RETRY_AFTER_SECONDS);
      case MFA_VERIFY_PATH -> enforce(response, MFA_POLICY, rateLimiter.checkMfaVerifyByIp(ip),
          "Too many MFA attempts from this IP. Try again later.", MFA_RETRY_AFTER_SECONDS);
      default -> { /* path is not IP-throttled — let the chain handle it */ }
    }
  }

  /**
   * Publishes the {@code RateLimit}/{@code RateLimit-Policy} headers for one bucket, then turns an
   * exhausted bucket into the canonical {@link RateLimitExceededException}. Headers are written
   * unconditionally (the standard's proactive signal); the throw only follows when the snapshot says
   * the request was not allowed.
   *
   * @param response          the response to decorate with rate-limit headers
   * @param policyName        the {@code RateLimit} partition name for this endpoint
   * @param snapshot          the consumption outcome — source of quota, window, remaining, reset, allowed
   * @param message           detail surfaced in the {@code application/problem+json} body on a 429
   * @param retryAfterSeconds back-off hint emitted as the {@code Retry-After} header on a 429
   */
  private static void enforce(
      HttpServletResponse response,
      String policyName,
      RateLimitSnapshot snapshot,
      String message,
      int retryAfterSeconds
  ) {
    RateLimitHeaders.write(response, policyName,
        snapshot.quota(), snapshot.windowSeconds(),
        snapshot.remainingTokens(), snapshot.secondsToReset());
    if (!snapshot.allowed()) {
      throw new RateLimitExceededException(message, retryAfterSeconds);
    }
  }

  private static String requestPath(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String contextPath = request.getContextPath();
    if (uri == null) {
      return "";
    }
    if (contextPath != null && !contextPath.isBlank() && uri.startsWith(contextPath)) {
      return uri.substring(contextPath.length());
    }
    return uri;
  }
}
