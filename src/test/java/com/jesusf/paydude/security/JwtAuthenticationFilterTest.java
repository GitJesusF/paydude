package com.jesusf.paydude.security;

import com.jesusf.paydude.enums.UserStatus;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link JwtAuthenticationFilter}.
 *
 * <p>The filter is the single chokepoint that translates a Bearer JWT into a populated
 * {@link SecurityContextHolder}. Every authenticated request in the API passes through it, so its
 * branches need direct coverage. Tests are grouped into six {@code @Nested} classes that mirror
 * the filter's decision tree:
 *
 * <ul>
 *   <li>{@code PassThrough} — no header, wrong scheme, already authenticated.</li>
 *   <li>{@code PublicEndpointSkips} — permitAll endpoints bypass JWT parsing entirely.</li>
 *   <li>{@code TokenFailures} — invalid signature, expired token, malformed input.</li>
 *   <li>{@code ClaimFailures} — well-signed token missing mandatory claims.</li>
 *   <li>{@code AccountStateFailures} — token is valid but the user state forbids access.</li>
 *   <li>{@code HappyPath} — a fully valid token populates the security context.</li>
 * </ul>
 *
 * <p>The filter never writes to the response directly: every failure is handed off to the resolver
 * so that the per-concern advice classes produce the canonical {@code ProblemDetail} JSON. These
 * tests assert that contract via {@code verify(resolver, ...)}.
 */
@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

  private static final String VALID_TOKEN = "header.payload.signature";
  private static final String AUTH_HEADER = "Authorization";
  private static final String BEARER_TOKEN = "Bearer " + VALID_TOKEN;

  private static final Long USER_ID = 42L;
  private static final String USER_SUBJECT = USER_ID.toString();
  private static final String USER_ROLE = "ROLE_USER";

  @Mock
  private JwtService jwtService;

  @Mock
  private HandlerExceptionResolver resolver;

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  @Mock
  private FilterChain filterChain;

  @InjectMocks
  private JwtAuthenticationFilter filter;

  /**
   * The filter writes to the static {@link SecurityContextHolder}; clearing it between tests
   * prevents authentication from leaking across cases (especially after the happy path).
   */
  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Nested
  @DisplayName("Pass-through — the filter must not attempt to parse the token")
  class PassThrough {

    @Test
    @DisplayName("Pass-through when the Authorization header is missing — no parsing, no resolver call")
    void passesThroughWhenHeaderIsMissing() throws Exception {
      when(request.getHeader(AUTH_HEADER)).thenReturn(null);

      filter.doFilterInternal(request, response, filterChain);

      verify(filterChain).doFilter(request, response);
      verify(jwtService, never()).parseClaims(anyString());
      verify(resolver, never()).resolveException(any(), any(), any(), any());
      assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("Pass-through when the scheme is not 'Bearer ' — protects against accidentally parsing Basic auth")
    void passesThroughWhenSchemeIsNotBearer() throws Exception {
      when(request.getHeader(AUTH_HEADER)).thenReturn("Basic dXNlcjpwYXNz");

      filter.doFilterInternal(request, response, filterChain);

      verify(filterChain).doFilter(request, response);
      verify(jwtService, never()).parseClaims(anyString());
    }

    @Test
    @DisplayName("Pass-through when the SecurityContext already has an authentication — avoids re-authenticating "
        + "requests that have been pre-authenticated by an earlier filter")
    void passesThroughWhenAlreadyAuthenticated() throws Exception {
      when(request.getHeader(AUTH_HEADER)).thenReturn(BEARER_TOKEN);
      SecurityContextHolder.getContext().setAuthentication(
          new UsernamePasswordAuthenticationToken("preAuth", null)
      );

      filter.doFilterInternal(request, response, filterChain);

      verify(filterChain).doFilter(request, response);
      verify(jwtService, never()).parseClaims(anyString());
    }
  }

  @Nested
  @DisplayName("Public endpoint skips — permitAll routes bypass JWT parsing")
  class PublicEndpointSkips {

    @Test
    @DisplayName("Skips the public token endpoints even when a stale Bearer header is present")
    void skipsAuthEndpointsEvenWhenBearerHeaderIsPresent() throws Exception {
      // Refresh/logout authenticate with the opaque refresh token in the body; a client that
      // still sends an expired access token by default must not be rejected before the
      // controller ever sees the refresh token.
      when(request.getRequestURI()).thenReturn("/v1/auth/refresh");
      lenient().when(request.getHeader(AUTH_HEADER)).thenReturn("Bearer expired.access.token");

      filter.doFilter(request, response, filterChain);

      verify(filterChain).doFilter(request, response);
      verify(request, never()).getHeader(AUTH_HEADER);
      verify(jwtService, never()).parseClaims(anyString());
      verify(resolver, never()).resolveException(any(), any(), any(), any());
      assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("Skips exactly the listed token endpoints; unlisted /v1/auth/** routes fail closed")
    void skipsExactTokenEndpointsOnly() throws Exception {
      assertTrue(shouldSkip("/v1/auth/register"));
      assertTrue(shouldSkip("/v1/auth/login"));
      assertTrue(shouldSkip("/v1/auth/refresh"));
      assertTrue(shouldSkip("/v1/auth/logout"));

      assertFalse(shouldSkip("/v1/auth/sessions"));
      assertFalse(shouldSkip("/v1/auth/login/history"));
    }

    @Test
    @DisplayName("Skips Swagger UI and OpenAPI endpoints")
    void skipsSwaggerAndApiDocsEndpoints() throws Exception {
      assertTrue(shouldSkip("/v3/api-docs"));
      assertTrue(shouldSkip("/v3/api-docs/swagger-config"));
      assertTrue(shouldSkip("/swagger-ui/index.html"));
      assertTrue(shouldSkip("/swagger-ui.html"));
    }

    @Test
    @DisplayName("Does not skip protected API endpoints")
    void doesNotSkipProtectedApiEndpoints() throws Exception {
      assertFalse(shouldSkip("/v1/accounts/me"));
      assertFalse(shouldSkip("/v1/transactions"));
    }
  }

  @Nested
  @DisplayName("Token failures — JWT is structurally invalid; all surface as BadCredentialsException")
  class TokenFailures {

    @Test
    @DisplayName("Forwards BadCredentialsException via the resolver when the signature is invalid")
    void forwardsBadCredentialsWhenSignatureFails() throws Exception {
      when(request.getHeader(AUTH_HEADER)).thenReturn(BEARER_TOKEN);
      when(jwtService.parseClaims(VALID_TOKEN)).thenThrow(new SignatureException("bad signature"));

      filter.doFilterInternal(request, response, filterChain);

      Exception forwarded = captureForwardedException();
      assertInstanceOf(BadCredentialsException.class, forwarded);
      // The client only ever sees the generic 401; the jjwt detail survives as the cause for
      // server-side logs.
      assertEquals(SignatureException.class, forwarded.getCause().getClass(),
          "The original JwtException must be preserved as the cause for traceability");
      // RFC 6750 §3: a presented-and-rejected token gets the refined challenge.
      verify(response).setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
      verify(filterChain, never()).doFilter(request, response);
      assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("Forwards BadCredentialsException via the resolver when the token is expired")
    void forwardsBadCredentialsWhenTokenIsExpired() throws Exception {
      // ExpiredJwtException's header/claims arguments are never inspected by the filter — only
      // the exception type matters.
      when(request.getHeader(AUTH_HEADER)).thenReturn(BEARER_TOKEN);
      when(jwtService.parseClaims(VALID_TOKEN))
          .thenThrow(new ExpiredJwtException(null, null, "expired"));

      filter.doFilterInternal(request, response, filterChain);

      Exception forwarded = captureForwardedException();
      assertInstanceOf(BadCredentialsException.class, forwarded);
    }

    @Test
    @DisplayName("Forwards BadCredentialsException when the parser raises IllegalArgumentException — covers "
        + "empty / null tokens that jjwt rejects before any signature work")
    void forwardsBadCredentialsOnIllegalArgument() throws Exception {
      // "Bearer " with nothing after the scheme extracts "" as the token.
      when(request.getHeader(AUTH_HEADER)).thenReturn("Bearer ");
      when(jwtService.parseClaims("")).thenThrow(new IllegalArgumentException("token is empty"));

      filter.doFilterInternal(request, response, filterChain);

      Exception forwarded = captureForwardedException();
      assertInstanceOf(BadCredentialsException.class, forwarded);
    }
  }

  @Nested
  @DisplayName("Claim failures — well-signed token missing mandatory claims is treated as bad credentials")
  class ClaimFailures {

    @Test
    @DisplayName("Forwards BadCredentialsException when the token has no userId claim")
    void forwardsBadCredentialsWhenUserIdClaimIsMissing() throws Exception {
      Claims claims = stubClaims(null, USER_SUBJECT, UserStatus.ACTIVE);
      stubBearerWithClaims(claims);

      filter.doFilterInternal(request, response, filterChain);

      Exception forwarded = captureForwardedException();
      assertInstanceOf(BadCredentialsException.class, forwarded);
      assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("Forwards BadCredentialsException when the token has no subject claim")
    void forwardsBadCredentialsWhenSubjectClaimIsMissing() throws Exception {
      Claims claims = stubClaims(USER_ID, null, UserStatus.ACTIVE);
      stubBearerWithClaims(claims);

      filter.doFilterInternal(request, response, filterChain);

      assertInstanceOf(BadCredentialsException.class, captureForwardedException());
    }

    @Test
    @DisplayName("Forwards BadCredentialsException when the subject does not match the userId claim")
    void forwardsBadCredentialsWhenSubjectDoesNotMatchUserId() throws Exception {
      Claims claims = stubClaims(USER_ID, "999", UserStatus.ACTIVE);
      stubBearerWithClaims(claims);

      filter.doFilterInternal(request, response, filterChain);

      assertInstanceOf(BadCredentialsException.class, captureForwardedException());
    }

    @Test
    @DisplayName("Forwards BadCredentialsException when the token has no status claim")
    void forwardsBadCredentialsWhenStatusClaimIsMissing() throws Exception {
      Claims claims = stubClaims(USER_ID, USER_SUBJECT, null);
      stubBearerWithClaims(claims);

      filter.doFilterInternal(request, response, filterChain);

      assertInstanceOf(BadCredentialsException.class, captureForwardedException());
    }
  }

  @Nested
  @DisplayName("Account-state failures — valid token but user state forbids access")
  class AccountStateFailures {

    @Test
    @DisplayName("Forwards LockedException when the token's status is LOCKED — surfaces as HTTP 423")
    void forwardsLockedExceptionWhenStatusIsLocked() throws Exception {
      Claims claims = stubClaims(USER_ID, USER_SUBJECT, UserStatus.LOCKED);
      stubBearerWithClaims(claims);

      filter.doFilterInternal(request, response, filterChain);

      assertInstanceOf(LockedException.class, captureForwardedException());
      // RFC 6750: the WWW-Authenticate challenge belongs to 401 ("authenticate and retry");
      // re-authenticating does not cure a 423, so it must not be emitted here.
      verify(response, never()).setHeader(eq("WWW-Authenticate"), anyString());
      assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("Forwards DisabledException when the token's status is SUSPENDED — surfaces as HTTP 403")
    void forwardsDisabledExceptionWhenStatusIsSuspended() throws Exception {
      Claims claims = stubClaims(USER_ID, USER_SUBJECT, UserStatus.SUSPENDED);
      stubBearerWithClaims(claims);

      filter.doFilterInternal(request, response, filterChain);

      assertInstanceOf(DisabledException.class, captureForwardedException());
      // Same reasoning as LOCKED: a 403 carries no re-authentication challenge.
      verify(response, never()).setHeader(eq("WWW-Authenticate"), anyString());
    }

    @Test
    @DisplayName("Forwards DisabledException when the token's status is CLOSED — same path as SUSPENDED, "
        + "ensures we treat both terminal disabled states the same way")
    void forwardsDisabledExceptionWhenStatusIsClosed() throws Exception {
      Claims claims = stubClaims(USER_ID, USER_SUBJECT, UserStatus.CLOSED);
      stubBearerWithClaims(claims);

      filter.doFilterInternal(request, response, filterChain);

      assertInstanceOf(DisabledException.class, captureForwardedException());
    }

    @Test
    @DisplayName("Lock check wins over account-expiry check — a LOCKED user with a past accountExpiresAt "
        + "must still surface as LockedException, mirroring DefaultPreAuthenticationChecks order")
    void lockCheckWinsOverAccountExpiryCheck() throws Exception {
      Claims claims = stubClaims(USER_ID, USER_SUBJECT, UserStatus.LOCKED);
      when(jwtService.extractAccountExpiresAt(claims)).thenReturn(Instant.now().minus(1, ChronoUnit.DAYS));
      stubBearerWithClaims(claims);

      filter.doFilterInternal(request, response, filterChain);

      assertInstanceOf(LockedException.class, captureForwardedException());
    }

    @Test
    @DisplayName("Forwards AccountExpiredException when accountExpiresAt has already passed — even if the JWT "
        + "itself is still cryptographically valid, the time check is evaluated against the current clock")
    void forwardsAccountExpiredExceptionWhenAccountTimeoutPassed() throws Exception {
      Claims claims = stubClaims(USER_ID, USER_SUBJECT, UserStatus.ACTIVE);
      when(jwtService.extractAccountExpiresAt(claims)).thenReturn(Instant.now().minus(1, ChronoUnit.DAYS));
      stubBearerWithClaims(claims);

      filter.doFilterInternal(request, response, filterChain);

      assertInstanceOf(AccountExpiredException.class, captureForwardedException());
    }

    @Test
    @DisplayName("Forwards CredentialsExpiredException when credentialsExpireAt has already passed — forces "
        + "the user to rotate the password before issuing a new token")
    void forwardsCredentialsExpiredExceptionWhenRotationDeadlinePassed() throws Exception {
      Claims claims = stubClaims(USER_ID, USER_SUBJECT, UserStatus.ACTIVE);
      when(jwtService.extractCredentialsExpireAt(claims)).thenReturn(Instant.now().minus(1, ChronoUnit.DAYS));
      stubBearerWithClaims(claims);

      filter.doFilterInternal(request, response, filterChain);

      assertInstanceOf(CredentialsExpiredException.class, captureForwardedException());
    }
  }

  @Nested
  @DisplayName("Happy path — a fully valid token populates the SecurityContext")
  class HappyPath {

    @Test
    @DisplayName("Populates the SecurityContext with a SecurityUser and the role authority on a valid token")
    void populatesSecurityContextOnValidToken() throws Exception {
      Claims claims = stubClaims(USER_ID, USER_SUBJECT, UserStatus.ACTIVE);
      when(jwtService.extractRole(claims)).thenReturn(USER_ROLE);
      stubBearerWithClaims(claims);

      filter.doFilterInternal(request, response, filterChain);

      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      assertNotNull(authentication, "A valid token must populate the SecurityContext");
      assertInstanceOf(SecurityUser.class, authentication.getPrincipal());

      SecurityUser principal = (SecurityUser) authentication.getPrincipal();
      assertEquals(USER_ID, principal.id());
      assertEquals("", principal.getUsername(), "JWT-authenticated principals must not carry email PII");
      assertEquals(UserStatus.ACTIVE, principal.status());
      // Authority order is not contractual — presence of the role is.
      assertTrue(authentication.getAuthorities().stream()
              .anyMatch(a -> USER_ROLE.equals(a.getAuthority())),
          "Role claim must surface as a GrantedAuthority for hasRole()/hasAuthority() checks");

      verify(filterChain, times(1)).doFilter(request, response);
      verify(resolver, never()).resolveException(any(), any(), any(), any());
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  /**
   * Builds a {@link Claims} mock and primes {@link JwtService} to return the supplied token
   * identity fields. Optional claims (role, accountExpiresAt, credentialsExpireAt) default to null
   * and can be overridden per-test before the call to {@link #stubBearerWithClaims(Claims)}.
   *
   * <p>{@code lenient()} is used because not every branch under test reaches every extractor: a
   * test that exits early on a missing userId will never hit {@code extractRole}, and Mockito
   * would otherwise flag those stubs as unnecessary.
   */
  private Claims stubClaims(Long userId, String subject, UserStatus status) {
    Claims claims = mock(Claims.class);
    lenient().when(jwtService.extractSubject(claims)).thenReturn(subject);
    lenient().when(jwtService.extractUserId(claims)).thenReturn(userId);
    lenient().when(jwtService.extractUserStatus(claims)).thenReturn(status);
    lenient().when(jwtService.extractRole(claims)).thenReturn(null);
    lenient().when(jwtService.extractAccountExpiresAt(claims)).thenReturn(null);
    lenient().when(jwtService.extractCredentialsExpireAt(claims)).thenReturn(null);
    return claims;
  }

  private void stubBearerWithClaims(Claims claims) {
    when(request.getHeader(AUTH_HEADER)).thenReturn(BEARER_TOKEN);
    when(jwtService.parseClaims(VALID_TOKEN)).thenReturn(claims);
  }

  private boolean shouldSkip(String path) throws Exception {
    when(request.getRequestURI()).thenReturn(path);
    return filter.shouldNotFilter(request);
  }

  /**
   * Captures the exception forwarded to the {@link HandlerExceptionResolver} so each test can
   * assert its type without relying on the resolver mock to propagate the failure to the test.
   */
  private Exception captureForwardedException() {
    ArgumentCaptor<Exception> exCaptor = ArgumentCaptor.forClass(Exception.class);
    verify(resolver, times(1)).resolveException(
        any(HttpServletRequest.class),
        any(HttpServletResponse.class),
        isNull(),
        exCaptor.capture()
    );
    return exCaptor.getValue();
  }
}
