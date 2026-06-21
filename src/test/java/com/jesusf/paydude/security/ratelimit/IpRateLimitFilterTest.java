package com.jesusf.paydude.security.ratelimit;

import com.jesusf.paydude.exception.RateLimitExceededException;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.HandlerExceptionResolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IpRateLimitFilter}.
 *
 * <p>The filter sits at the earliest position in the servlet chain and is the only barrier between
 * the auth endpoints and a per-IP brute force. The matrix below pins the axes that determine its
 * behaviour: method (only POST counts), path (only login/register/refresh/mfa-verify match), bucket outcome
 * (allowed vs. blocked), out-of-scope traffic (must pass through untouched), and — new — the IETF
 * {@code RateLimit} headers emitted on every in-scope response.
 *
 * <p>The collaborators ({@link AuthRateLimiter}, {@link HandlerExceptionResolver}) are mocked: the
 * limiter is exercised by its own test and the resolver is provided by Spring at runtime. The filter
 * renders the headers purely from the {@link RateLimitSnapshot} the limiter returns, so the stubs
 * below also carry the quota/window the header must advertise — proving the filter forwards the
 * snapshot's numbers rather than hard-coding anything.
 */
@ExtendWith(MockitoExtension.class)
class IpRateLimitFilterTest {

  private static final String LOGIN_PATH = "/v1/auth/login";
  private static final String REGISTER_PATH = "/v1/auth/register";
  private static final String REFRESH_PATH = "/v1/auth/refresh";
  private static final String MFA_VERIFY_PATH = "/v1/auth/mfa/verify";
  private static final String CLIENT_IP = "203.0.113.42";

  // Expected RateLimit-Policy strings — derived from the quota/window each stubbed snapshot carries,
  // so they double as proof the filter renders the snapshot's values per endpoint.
  private static final String POLICY_LOGIN = "\"login\";q=20;w=60";
  private static final String POLICY_REGISTER = "\"register\";q=5;w=3600";
  private static final String POLICY_REFRESH = "\"refresh\";q=60;w=3600";
  private static final String POLICY_MFA = "\"mfa\";q=10;w=60";

  @Mock
  private AuthRateLimiter rateLimiter;

  @Mock
  private HandlerExceptionResolver resolver;

  private IpRateLimitFilter filter;

  @BeforeEach
  void setUp() {
    filter = new IpRateLimitFilter(rateLimiter, resolver);
  }

  // -----------------------------------------------------------------------------------------------
  // POST /v1/auth/login
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("POST /v1/auth/login — consumes the login-by-IP bucket")
  class PostLogin {

    @Test
    @DisplayName("allowed by limiter → chain proceeds, RateLimit headers published, resolver untouched")
    void allowedRequestPassesThrough() throws Exception {
      when(rateLimiter.checkLoginByIp(CLIENT_IP)).thenReturn(new RateLimitSnapshot(true, 20, 60, 19, 55));

      MockHttpServletResponse response = new MockHttpServletResponse();
      MockFilterChain chain = new MockFilterChain();
      filter.doFilter(postRequest(LOGIN_PATH), response, chain);

      assertEquals(LOGIN_PATH, ((MockHttpServletRequest) chain.getRequest()).getRequestURI(),
          "filter must delegate to the chain when the bucket allows the request");
      // RateLimit headers are published proactively on the 2xx — the point of the IETF draft:
      // a well-behaved client backs off before ever hitting the limit.
      assertEquals(POLICY_LOGIN, response.getHeader("RateLimit-Policy"));
      assertEquals("\"login\";r=19;t=55", response.getHeader("RateLimit"));
      verifyNoInteractions(resolver);
    }

    @Test
    @DisplayName("mounted context path is stripped before matching the login endpoint")
    void contextPathDoesNotBypassLoginThrottle() throws Exception {
      when(rateLimiter.checkLoginByIp(CLIENT_IP)).thenReturn(new RateLimitSnapshot(true, 20, 60, 19, 55));

      MockHttpServletRequest request = postRequest("/paydude" + LOGIN_PATH);
      request.setContextPath("/paydude");

      MockFilterChain chain = new MockFilterChain();
      filter.doFilter(request, new MockHttpServletResponse(), chain);

      assertEquals("/paydude" + LOGIN_PATH,
          ((MockHttpServletRequest) chain.getRequest()).getRequestURI());
      verify(rateLimiter).checkLoginByIp(CLIENT_IP);
      verifyNoInteractions(resolver);
    }

    @Test
    @DisplayName("blocked by limiter → RateLimit headers still set, resolver receives the exception, chain not called")
    void blockedRequestIsForwardedToResolver() throws Exception {
      when(rateLimiter.checkLoginByIp(CLIENT_IP)).thenReturn(new RateLimitSnapshot(false, 20, 60, 0, 60));

      MockHttpServletRequest request = postRequest(LOGIN_PATH);
      MockHttpServletResponse response = new MockHttpServletResponse();
      FilterChain chain = Mockito.mock(FilterChain.class);

      filter.doFilter(request, response, chain);

      verify(chain, never()).doFilter(any(), any());

      // Headers are written before the 429 is forwarded, so they survive in the response next to
      // the Retry-After that RateLimitExceptionHandler adds.
      assertEquals(POLICY_LOGIN, response.getHeader("RateLimit-Policy"));
      assertEquals("\"login\";r=0;t=60", response.getHeader("RateLimit"));

      // Must be exactly RateLimitExceededException — a generic runtime would fall through to the
      // catch-all advice and surface as a 500.
      ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
      verify(resolver).resolveException(eq(request), eq(response), isNull(), captor.capture());

      RateLimitExceededException thrown =
          assertInstanceOf(RateLimitExceededException.class, captor.getValue());
      assertEquals(60, thrown.getRetryAfterSeconds(),
          "login retry-after hint must match the documented contract");
    }
  }

  // -----------------------------------------------------------------------------------------------
  // POST /v1/auth/register
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("POST /v1/auth/register — consumes the register-by-IP bucket")
  class PostRegister {

    @Test
    @DisplayName("allowed by limiter → chain proceeds, RateLimit headers published, resolver untouched")
    void allowedRequestPassesThrough() throws Exception {
      when(rateLimiter.checkRegisterByIp(CLIENT_IP)).thenReturn(new RateLimitSnapshot(true, 5, 3600, 4, 3600));

      MockHttpServletResponse response = new MockHttpServletResponse();
      MockFilterChain chain = new MockFilterChain();
      filter.doFilter(postRequest(REGISTER_PATH), response, chain);

      assertEquals(REGISTER_PATH, ((MockHttpServletRequest) chain.getRequest()).getRequestURI());
      assertEquals(POLICY_REGISTER, response.getHeader("RateLimit-Policy"));
      assertEquals("\"register\";r=4;t=3600", response.getHeader("RateLimit"));
      verifyNoInteractions(resolver);
    }

    @Test
    @DisplayName("blocked by limiter → resolver receives RateLimitExceededException with 1 h retry-after")
    void blockedRequestIsForwardedToResolver() throws Exception {
      when(rateLimiter.checkRegisterByIp(CLIENT_IP)).thenReturn(new RateLimitSnapshot(false, 5, 3600, 0, 3600));

      MockHttpServletRequest request = postRequest(REGISTER_PATH);
      MockHttpServletResponse response = new MockHttpServletResponse();
      FilterChain chain = Mockito.mock(FilterChain.class);

      filter.doFilter(request, response, chain);

      verify(chain, never()).doFilter(any(), any());
      assertEquals(POLICY_REGISTER, response.getHeader("RateLimit-Policy"));

      ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
      verify(resolver).resolveException(eq(request), eq(response), isNull(), captor.capture());

      RateLimitExceededException thrown =
          assertInstanceOf(RateLimitExceededException.class, captor.getValue());
      assertEquals(3600, thrown.getRetryAfterSeconds(),
          "register retry-after hint must match the documented contract");
    }
  }

  // -----------------------------------------------------------------------------------------------
  // POST /v1/auth/refresh
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("POST /v1/auth/refresh — consumes the refresh-by-IP bucket")
  class PostRefresh {

    @Test
    @DisplayName("allowed by limiter → chain proceeds, RateLimit headers published, resolver untouched")
    void allowedRequestPassesThrough() throws Exception {
      when(rateLimiter.checkRefreshByIp(CLIENT_IP)).thenReturn(new RateLimitSnapshot(true, 60, 3600, 7, 30));

      MockHttpServletResponse response = new MockHttpServletResponse();
      MockFilterChain chain = new MockFilterChain();
      filter.doFilter(postRequest(REFRESH_PATH), response, chain);

      assertEquals(REFRESH_PATH, ((MockHttpServletRequest) chain.getRequest()).getRequestURI());
      assertEquals(POLICY_REFRESH, response.getHeader("RateLimit-Policy"));
      assertEquals("\"refresh\";r=7;t=30", response.getHeader("RateLimit"));
      verifyNoInteractions(resolver);
    }

    @Test
    @DisplayName("blocked by limiter → resolver receives RateLimitExceededException with 1 min retry-after")
    void blockedRequestIsForwardedToResolver() throws Exception {
      when(rateLimiter.checkRefreshByIp(CLIENT_IP)).thenReturn(new RateLimitSnapshot(false, 60, 3600, 0, 60));

      MockHttpServletRequest request = postRequest(REFRESH_PATH);
      MockHttpServletResponse response = new MockHttpServletResponse();
      FilterChain chain = Mockito.mock(FilterChain.class);

      filter.doFilter(request, response, chain);

      verify(chain, never()).doFilter(any(), any());
      assertEquals(POLICY_REFRESH, response.getHeader("RateLimit-Policy"));

      ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
      verify(resolver).resolveException(eq(request), eq(response), isNull(), captor.capture());

      RateLimitExceededException thrown =
          assertInstanceOf(RateLimitExceededException.class, captor.getValue());
      assertEquals(60, thrown.getRetryAfterSeconds(),
          "refresh retry-after hint must match the documented contract");
    }
  }

  // -----------------------------------------------------------------------------------------------
  // POST /v1/auth/mfa/verify
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("POST /v1/auth/mfa/verify — consumes the strict mfa-by-IP bucket")
  class PostMfaVerify {

    @Test
    @DisplayName("allowed by limiter → chain proceeds, RateLimit headers published, resolver untouched")
    void allowedRequestPassesThrough() throws Exception {
      when(rateLimiter.checkMfaVerifyByIp(CLIENT_IP)).thenReturn(new RateLimitSnapshot(true, 10, 60, 9, 42));

      MockHttpServletResponse response = new MockHttpServletResponse();
      MockFilterChain chain = new MockFilterChain();
      filter.doFilter(postRequest(MFA_VERIFY_PATH), response, chain);

      assertEquals(MFA_VERIFY_PATH, ((MockHttpServletRequest) chain.getRequest()).getRequestURI());
      assertEquals(POLICY_MFA, response.getHeader("RateLimit-Policy"));
      assertEquals("\"mfa\";r=9;t=42", response.getHeader("RateLimit"));
      verifyNoInteractions(resolver);
    }

    @Test
    @DisplayName("blocked by limiter → resolver receives RateLimitExceededException with 1 min retry-after")
    void blockedRequestIsForwardedToResolver() throws Exception {
      // The strictest bucket in the filter's scope: a 6-digit TOTP space is the one place online
      // guessing is arithmetically viable, and every caller here has already proven the password.
      when(rateLimiter.checkMfaVerifyByIp(CLIENT_IP)).thenReturn(new RateLimitSnapshot(false, 10, 60, 0, 60));

      MockHttpServletRequest request = postRequest(MFA_VERIFY_PATH);
      MockHttpServletResponse response = new MockHttpServletResponse();
      FilterChain chain = Mockito.mock(FilterChain.class);

      filter.doFilter(request, response, chain);

      verify(chain, never()).doFilter(any(), any());
      assertEquals(POLICY_MFA, response.getHeader("RateLimit-Policy"));
      assertEquals("\"mfa\";r=0;t=60", response.getHeader("RateLimit"));

      ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
      verify(resolver).resolveException(eq(request), eq(response), isNull(), captor.capture());

      RateLimitExceededException thrown =
          assertInstanceOf(RateLimitExceededException.class, captor.getValue());
      assertEquals(60, thrown.getRetryAfterSeconds(),
          "mfa retry-after hint must match the documented contract");
    }
  }

  // -----------------------------------------------------------------------------------------------
  // Out-of-scope traffic must pass through without consuming any bucket or writing headers
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("Out-of-scope requests — pass through without touching any bucket")
  class OutOfScope {

    @Test
    @DisplayName("GET on a throttled path is ignored (no bucket consumed, no headers)")
    void getOnThrottledPathDoesNotConsume() throws Exception {
      // Counting non-POSTs would let an attacker drain a NAT'd IP's bucket with GETs (which 405
      // anyway), locking out every legitimate user behind that NAT.
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.setMethod("GET");
      request.setRequestURI(LOGIN_PATH);
      request.setRemoteAddr(CLIENT_IP);

      MockHttpServletResponse response = new MockHttpServletResponse();
      MockFilterChain chain = new MockFilterChain();
      filter.doFilter(request, response, chain);

      verifyNoInteractions(rateLimiter, resolver);
      assertEquals(LOGIN_PATH, ((MockHttpServletRequest) chain.getRequest()).getRequestURI());
      assertNull(response.getHeader("RateLimit"), "out-of-scope traffic must not advertise quota");
    }

    @Test
    @DisplayName("POST on a path outside the auth namespace passes through")
    void postOnUnrelatedPathPassesThrough() throws Exception {
      MockFilterChain chain = new MockFilterChain();
      filter.doFilter(
          postRequest("/v1/transactions/transfer"),
          new MockHttpServletResponse(),
          chain
      );

      verifyNoInteractions(rateLimiter, resolver);
      assertEquals("/v1/transactions/transfer",
          ((MockHttpServletRequest) chain.getRequest()).getRequestURI());
    }
  }

  // -----------------------------------------------------------------------------------------------
  // Bucket isolation between login and register
  // -----------------------------------------------------------------------------------------------

  @Test
  @DisplayName("login and register paths consume separate buckets")
  void loginAndRegisterUseSeparateBuckets() throws Exception {
    when(rateLimiter.checkLoginByIp(anyString())).thenReturn(new RateLimitSnapshot(true, 20, 60, 19, 55));
    when(rateLimiter.checkRegisterByIp(anyString())).thenReturn(new RateLimitSnapshot(true, 5, 3600, 4, 3600));

    filter.doFilter(postRequest(LOGIN_PATH), new MockHttpServletResponse(), new MockFilterChain());
    filter.doFilter(postRequest(REGISTER_PATH), new MockHttpServletResponse(), new MockFilterChain());

    // A crossed invocation (login consuming checkRegisterByIp) would mean the path dispatch is broken.
    verify(rateLimiter, times(1)).checkLoginByIp(CLIENT_IP);
    verify(rateLimiter, times(1)).checkRegisterByIp(CLIENT_IP);
    verify(rateLimiter, never()).tryLoginByEmail(anyString());
  }

  // -----------------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------------

  private static MockHttpServletRequest postRequest(String uri) {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setMethod("POST");
    request.setRequestURI(uri);
    request.setRemoteAddr(CLIENT_IP);
    return request;
  }
}
