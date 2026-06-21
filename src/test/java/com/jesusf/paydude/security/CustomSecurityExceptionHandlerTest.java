package com.jesusf.paydude.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.servlet.HandlerExceptionResolver;

import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link CustomSecurityExceptionHandler}.
 *
 * <p>The handler is small but load-bearing: it bridges the Spring Security filter chain to the
 * MVC exception pipeline. Without it, 401/403 errors raised inside the security filters would
 * be written by Spring's default entry points and access-denied handlers — producing a JSON
 * shape that does <b>not</b> match the rest of the API. Two formats coexisting on the wire is
 * a contract bug from the client's perspective, so the contract worth verifying is exactly:
 *
 * <ul>
 *   <li>Both methods forward the original exception to the {@link HandlerExceptionResolver}
 *       <b>unchanged</b> (no wrapping, no rethrow) — wrapping would change the type and the
 *       advice's {@code @ExceptionHandler} would no longer match.</li>
 *   <li>The handler chain is {@code (request, response, null, exception)} — the {@code null}
 *       handler position is what tells the resolver to walk MVC's exception chain instead of
 *       trying to attribute the failure to a specific controller method.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class CustomSecurityExceptionHandlerTest {

  @Mock
  private HandlerExceptionResolver resolver;

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  @InjectMocks
  private CustomSecurityExceptionHandler handler;

  @Test
  @DisplayName("commence() forwards the AuthenticationException unchanged to the resolver — produces the same "
      + "ProblemDetail JSON as a controller-thrown exception")
  void commenceForwardsAuthenticationExceptionToResolver() {
    AuthenticationException authException = new BadCredentialsException("invalid credentials");

    handler.commence(request, response, authException);

    verify(resolver, times(1)).resolveException(
        same(request),
        same(response),
        isNull(),
        same(authException)
    );
  }

  @Test
  @DisplayName("handle() forwards the AccessDeniedException unchanged to the resolver — same JSON shape "
      + "as a 403 raised from inside a controller")
  void handleForwardsAccessDeniedExceptionToResolver() {
    AccessDeniedException accessDeniedException = new AccessDeniedException("forbidden");

    handler.handle(request, response, accessDeniedException);

    verify(resolver, times(1)).resolveException(
        same(request),
        same(response),
        isNull(),
        same(accessDeniedException)
    );
  }
}
