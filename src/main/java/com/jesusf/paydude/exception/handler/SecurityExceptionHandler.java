package com.jesusf.paydude.exception.handler;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Handles authentication and authorization failures from Spring Security. The specific subclasses
 * (BadCredentials, Locked, Disabled, AccountExpired, CredentialsExpired) come from
 * {@code SecurityUser}'s {@code UserDetails} contract; the generic {@code AuthenticationException}
 * and {@code AccessDeniedException} catch anything not covered by a specific handler.
 *
 * <p>Client-facing messages are intentionally generic to avoid leaking signals that aid account
 * enumeration or credential probing.
 */
@Slf4j
@Order(20)
@RestControllerAdvice
public class SecurityExceptionHandler {

  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<ProblemDetail> handleBadCredentials(BadCredentialsException ex, HttpServletRequest request) {
    // Audit-log the real cause (login mismatch vs invalid token) but expose a single, generic
    // message to the client. Differentiating helps attackers enumerate accounts or probe tokens.
    log.warn("401 Authentication Failed at {}: {}", request.getRequestURI(), ex.getMessage());
    return ErrorResponses.of(HttpStatus.UNAUTHORIZED, "authentication-failed", "Authentication Failed", "Invalid credentials or token", request);
  }

  @ExceptionHandler(AccountExpiredException.class)
  public ResponseEntity<ProblemDetail> handleAccountExpired(AccountExpiredException ex, HttpServletRequest request) {
    log.warn("401 Account Expired at {}", request.getRequestURI());
    return ErrorResponses.of(HttpStatus.UNAUTHORIZED, "account-expired", "Account Expired", "Your account access period has ended. Please contact support.", request);
  }

  @ExceptionHandler(CredentialsExpiredException.class)
  public ResponseEntity<ProblemDetail> handleCredentialsExpired(CredentialsExpiredException ex, HttpServletRequest request) {
    log.warn("401 Password Expired at {}", request.getRequestURI());
    return ErrorResponses.of(HttpStatus.UNAUTHORIZED, "password-expired", "Password Expired", "Your password has expired. Please reset it to continue.", request);
  }

  @ExceptionHandler(DisabledException.class)
  public ResponseEntity<ProblemDetail> handleDisabled(DisabledException ex, HttpServletRequest request) {
    log.warn("403 Account Disabled at {}", request.getRequestURI());
    return ErrorResponses.of(HttpStatus.FORBIDDEN, "account-disabled", "Account Disabled", "Your account is not active. Please contact support.", request);
  }

  @ExceptionHandler(LockedException.class)
  public ResponseEntity<ProblemDetail> handleLocked(LockedException ex, HttpServletRequest request) {
    log.warn("423 Account Locked at {}", request.getRequestURI());
    return ErrorResponses.of(HttpStatus.LOCKED, "account-locked", "Account Locked", "Your account has been temporarily locked due to repeated failed login attempts. Please try again later.", request);
  }

  @ExceptionHandler(AuthenticationException.class)
  public ResponseEntity<ProblemDetail> handleAuthentication(AuthenticationException ex, HttpServletRequest request) {
    log.warn("401 Unauthorized at {}: {}", request.getRequestURI(), ex.getMessage());
    return ErrorResponses.of(HttpStatus.UNAUTHORIZED, "unauthorized", "Unauthorized", "Authentication is required to access this resource.", request);
  }

  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
    log.warn("403 Forbidden at {}: {}", request.getRequestURI(), ex.getMessage());
    return ErrorResponses.of(HttpStatus.FORBIDDEN, "forbidden", "Forbidden", "You do not have permission to access this resource.", request);
  }
}