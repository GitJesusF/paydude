package com.jesusf.paydude.exception.handler;

import com.jesusf.paydude.exception.RateLimitExceededException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Throttling responses. The {@code Retry-After} header is required by RFC 6585 §4 so clients can
 * back off without guessing — this is the one handler whose response wrapper diverges from the
 * shared helper because the header attachment forces a manual {@link ResponseEntity} build.
 */
@Slf4j
@Order(50)
@RestControllerAdvice
public class RateLimitExceptionHandler {

  @ExceptionHandler(RateLimitExceededException.class)
  public ResponseEntity<ProblemDetail> handleRateLimit(RateLimitExceededException ex, HttpServletRequest request) {
    log.warn("429 Too Many Requests at {} from IP {}: {}",
        request.getRequestURI(), request.getRemoteAddr(), ex.getMessage());

    ProblemDetail body = ErrorResponses.buildProblem(
        HttpStatus.TOO_MANY_REQUESTS,
        "too-many-requests",
        "Too Many Requests",
        ex.getMessage(),
        request,
        null
    );
    return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
        .header(HttpHeaders.RETRY_AFTER, String.valueOf(ex.getRetryAfterSeconds()))
        .body(body);
  }
}