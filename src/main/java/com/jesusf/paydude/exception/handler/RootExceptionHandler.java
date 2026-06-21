package com.jesusf.paydude.exception.handler;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Last-resort handler for anything no specific advice claims. Logs at ERROR with the full stack
 * trace because by definition we don't know the cause yet — this is the only handler whose
 * appearance in the logs should page someone.
 *
 * <p>{@code @Order(LOWEST_PRECEDENCE)} guarantees Spring evaluates the more specific advices first.
 */
@Slf4j
@Order(Ordered.LOWEST_PRECEDENCE)
@RestControllerAdvice
public class RootExceptionHandler {

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ProblemDetail> handleUnexpected(Exception ex, HttpServletRequest request) {
    log.error("Unexpected error occurred at {}: ", request.getRequestURI(), ex);
    return ErrorResponses.of(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "internal-server-error",
        "Internal Server Error",
        "An unexpected error occurred. Please contact support.",
        request
    );
  }
}