package com.jesusf.paydude.security;

import com.jesusf.paydude.enums.UserStatus;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

/**
 * Translates a {@code Bearer} JWT into a populated {@link SecurityContextHolder} on every
 * authenticated request.
 *
 * <p>All failure modes — bad signature, expired token, missing required claims, or a user/account
 * whose state has degraded since the token was issued — are forwarded through Spring MVC's
 * {@link HandlerExceptionResolver} so they reach the per-concern {@code @RestControllerAdvice}
 * handlers and produce the same {@code ProblemDetail} (RFC 9457) JSON shape as the rest of the
 * API. Writing to the response directly from a servlet filter would bypass that pipeline and leak
 * two error formats to clients.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private static final String AUTH_HEADER = "Authorization";
  private static final String BEARER_PREFIX = "Bearer ";
  private static final String AUTH_REGISTER_PATH = "/v1/auth/register";
  private static final String AUTH_LOGIN_PATH = "/v1/auth/login";
  private static final String AUTH_REFRESH_PATH = "/v1/auth/refresh";
  private static final String AUTH_LOGOUT_PATH = "/v1/auth/logout";
  // The MFA verify step authenticates with the challenge token in the BODY, not a Bearer header —
  // skipping it here for the same reason as refresh/logout: a stale Authorization header must not
  // pre-empt the credential the endpoint actually consumes.
  private static final String AUTH_MFA_VERIFY_PATH = "/v1/auth/mfa/verify";
  private static final String API_DOCS_PATH = "/v3/api-docs";
  private static final String API_DOCS_PATH_PREFIX = API_DOCS_PATH + "/";
  private static final String SWAGGER_UI_PATH = "/swagger-ui.html";
  private static final String SWAGGER_UI_PATH_PREFIX = "/swagger-ui/";
  private static final String JWT_PRINCIPAL_EMAIL = "";
  private static final String JWT_PRINCIPAL_PASSWORD = "";

  private final JwtService jwtService;

  @Qualifier("handlerExceptionResolver")
  private final HandlerExceptionResolver resolver;

  /**
   * Public token endpoints must stay public even when a browser or API client sends a stale
   * {@code Authorization: Bearer ...} header. Without this skip, an expired access token attached
   * to {@code /v1/auth/refresh} or {@code /v1/auth/logout} would be parsed and rejected before the
   * controller could process the opaque refresh token that actually authenticates those flows.
   *
   * <p>The list mirrors {@code SecurityConfig.securityFilterChain(...).permitAll()} for the API
   * chain. It is intentionally exact, not {@code /v1/auth/**}: a future management endpoint under
   * {@code /auth} must opt in to public access explicitly. Actuator is not listed here because it is
   * claimed by the separate, higher-precedence actuator security chain and never reaches this filter.
   */
  @Override
  protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
    String path = requestPath(request);
    return isAuthPath(path)
        || isApiDocsPath(path)
        || isSwaggerUiPath(path);
  }

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain
  ) throws ServletException, IOException {

    final String authHeader = request.getHeader(AUTH_HEADER);
    if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
      filterChain.doFilter(request, response);
      return;
    }

    if (SecurityContextHolder.getContext().getAuthentication() != null) {
      filterChain.doFilter(request, response);
      return;
    }

    try {
      final String jwt = authHeader.substring(BEARER_PREFIX.length());
      // Single parse: verifies signature and rejects expired tokens (jwt throws ExpiredJwtException).
      final Claims claims = jwtService.parseClaims(jwt);
      authenticate(request, claims);
      filterChain.doFilter(request, response);
    } catch (JwtException | IllegalArgumentException ex) {
      // Malformed, tampered, or expired token. Translate to a Spring Security exception so the
      // HandlerExceptionResolver / per-concern advice pipeline produces the canonical 401
      // ProblemDetail. The client is told only "authentication failed" — no token internals.
      SecurityContextHolder.clearContext();
      forwardAuthFailure(request, response, new BadCredentialsException("Invalid or expired token", ex));
    } catch (AuthenticationException ex) {
      // Account state checks below raise specific Spring Security exceptions
      // (Disabled/Locked/AccountExpired/CredentialsExpired). The per-concern security advice maps
      // each to its precise HTTP status (403 / 423 / 401 / 401).
      SecurityContextHolder.clearContext();
      forwardAuthFailure(request, response, ex);
    }
  }

  /**
   * Forwards an authentication failure that originated from a <em>presented</em> Bearer token to
   * the {@link HandlerExceptionResolver} pipeline, attaching the RFC 6750 §3 challenge when the
   * failure maps to a 401.
   *
   * <p>Because the filter only reaches this point when an {@code Authorization: Bearer} header was
   * supplied, the token itself is what failed — expired, tampered, or representing a degraded
   * account — so the challenge narrows to {@code error="invalid_token"}. The "no token at all"
   * case never reaches this filter branch; it surfaces later through
   * {@link CustomSecurityExceptionHandler}, which emits the bare {@code Bearer} challenge instead.
   *
   * <p>{@code DisabledException} (403) and {@code LockedException} (423) carry no challenge: the
   * RFC 6750 {@code WWW-Authenticate} header is the 401 contract ("authenticate, then retry"),
   * and re-authenticating cannot cure a disabled or locked account — emitting it there would be
   * an instruction the client can never satisfy.
   */
  private void forwardAuthFailure(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException ex
  ) {
    if (!(ex instanceof DisabledException || ex instanceof LockedException)) {
      response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
    }
    resolver.resolveException(request, response, null, ex);
  }

  private void authenticate(HttpServletRequest request, Claims claims) {
    final String subject = jwtService.extractSubject(claims);
    final Long userId = jwtService.extractUserId(claims);
    final UserStatus userStatus = jwtService.extractUserStatus(claims);

    // Reject tokens missing/inconsistent required claims rather than silently downgrading to ACTIVE.
    // A token that parses but lacks the claims we issue is suspicious (forged with a leaked
    // signing key by an attacker who didn't know the full claim set).
    if (subject == null || userId == null || userStatus == null || !subject.equals(userId.toString())) {
      throw new BadCredentialsException("Token is missing or inconsistent required claims");
    }

    final String role = jwtService.extractRole(claims);
    final Instant accountExpiresAt = jwtService.extractAccountExpiresAt(claims);
    final Instant credentialsExpireAt = jwtService.extractCredentialsExpireAt(claims);

    final List<GrantedAuthority> authorities = role != null
        ? List.of(new SimpleGrantedAuthority(role))
        : Collections.emptyList();

    // Access tokens embed neither email (no PII) nor a password (the token already authenticated);
    // a JWT-derived principal is never re-checked against a credential. Controllers authorize from id.
    // mfaEnabled is false by construction: an access token only exists after the second factor
    // (when enrolled) was satisfied, so MFA state is login-flow data, not a per-request authority.
    final SecurityUser userDetails = new SecurityUser(
        userId,
        JWT_PRINCIPAL_EMAIL,
        JWT_PRINCIPAL_PASSWORD,
        userStatus,
        accountExpiresAt,
        credentialsExpireAt,
        false,
        authorities
    );

    // Per-request state enforcement. Status changes since token issuance only take effect on the
    // next refresh (stateless JWT trade-off); time-based checks below are evaluated against the
    // current clock and therefore apply immediately.
    //
    // Order mirrors Spring Security's DefaultPreAuthenticationChecks (lock → enabled → account
    // expiry) followed by DefaultPostAuthenticationChecks (credentials expiry). Keeping this order
    // ensures that a JWT-authenticated request and a fresh login through DaoAuthenticationProvider
    // surface the same exception — and therefore the same HTTP status — for the same account state.
    // In particular, LOCKED must be reported as LockedException (HTTP 423): isEnabled() also returns
    // false for LOCKED, so the lock check has to run first or it would be masked as DisabledException.
    if (!userDetails.isAccountNonLocked()) {
      throw new LockedException("User account is locked");
    }
    if (!userDetails.isEnabled()) {
      throw new DisabledException("User account is not active");
    }
    if (!userDetails.isAccountNonExpired()) {
      throw new AccountExpiredException("User account has expired");
    }
    if (!userDetails.isCredentialsNonExpired()) {
      throw new CredentialsExpiredException("User credentials have expired");
    }

    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
        userDetails, null, userDetails.getAuthorities()
    );
    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    SecurityContextHolder.getContext().setAuthentication(authToken);
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

  private static boolean isAuthPath(String path) {
    return AUTH_REGISTER_PATH.equals(path)
        || AUTH_LOGIN_PATH.equals(path)
        || AUTH_REFRESH_PATH.equals(path)
        || AUTH_LOGOUT_PATH.equals(path)
        || AUTH_MFA_VERIFY_PATH.equals(path);
  }

  private static boolean isApiDocsPath(String path) {
    return API_DOCS_PATH.equals(path) || path.startsWith(API_DOCS_PATH_PREFIX);
  }

  private static boolean isSwaggerUiPath(String path) {
    return SWAGGER_UI_PATH.equals(path) || path.startsWith(SWAGGER_UI_PATH_PREFIX);
  }
}
