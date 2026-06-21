package com.jesusf.paydude.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * The Spring Security entry point for failures raised by the filter chain itself — implements
 * both {@link AuthenticationEntryPoint} (401: missing or invalid credentials) and
 * {@link AccessDeniedHandler} (403: authenticated but not authorized).
 *
 * <p>Instead of writing an error body directly, it forwards the exception through Spring MVC's
 * {@link HandlerExceptionResolver}. Security failures therefore reach the same per-concern
 * {@code @RestControllerAdvice} chain as every other error and produce an identical
 * {@code application/problem+json} response — clients never see a second error shape.
 */
@RequiredArgsConstructor
@Component
public class CustomSecurityExceptionHandler implements AuthenticationEntryPoint, AccessDeniedHandler {

  private static final String BEARER_PREFIX = "Bearer ";

  @Qualifier("handlerExceptionResolver")
  private final HandlerExceptionResolver resolver;

  /**
   * Handles a 401: no authentication, or authentication that the entry point itself rejects.
   *
   * <p>Emits the RFC 6750 §3 {@code WWW-Authenticate} challenge before forwarding, then lets the
   * resolver write the body. A {@code Bearer} token that was present but rejected gets
   * {@code error="invalid_token"}; a request with no token at all gets the bare {@code Bearer}
   * challenge — nothing is wrong to report, only a credential is missing.
   */
  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) {
    // RFC 6750 §3: a 401 to a Bearer-protected resource must carry a WWW-Authenticate
    // challenge so the client knows how to authenticate. We set it before forwarding to the
    // resolver — the resolver writes the ProblemDetail body but leaves response headers alone.
    // If the caller sent a Bearer token, the token itself was rejected (bad signature,
    // expired, degraded account) → error="invalid_token". If no token arrived at all, the
    // bare challenge is the correct response: nothing is wrong to report, only a missing
    // credential.
    String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (authorization != null && authorization.startsWith(BEARER_PREFIX)) {
      response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
    } else {
      response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
    }

    // Forward the 401 to the HandlerExceptionResolver so the per-concern advice produces the
    // standard ProblemDetail body.
    resolver.resolveException(request, response, null, authException);
  }

  /**
   * Handles a 403: the caller is authenticated but lacks the authority for the resource.
   * Forwarded to the resolver so the per-concern advice produces the standard ProblemDetail body.
   */
  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) {
    resolver.resolveException(request, response, null, accessDeniedException);
  }
}
