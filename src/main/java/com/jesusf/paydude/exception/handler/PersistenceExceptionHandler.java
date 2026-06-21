package com.jesusf.paydude.exception.handler;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.sql.SQLException;

/**
 * Persistence-layer failures surfaced by Spring Data: lost optimistic-lock races and DB-level
 * constraint violations. Messages are scrubbed to avoid leaking schema details (column names,
 * constraint identifiers) to clients.
 */
@Slf4j
@Order(40)
@RestControllerAdvice
public class PersistenceExceptionHandler {

  @ExceptionHandler(OptimisticLockingFailureException.class)
  public ResponseEntity<ProblemDetail> handleOptimisticLock(OptimisticLockingFailureException ex, HttpServletRequest request) {
    log.warn("409 Concurrency Error at {}: {}", request.getRequestURI(), ex.getMessage());
    return ErrorResponses.of(
        HttpStatus.CONFLICT,
        "concurrency-error",
        "Concurrency Error",
        "The data was updated by another transaction. Please refresh and try again.",
        request
    );
  }

  @ExceptionHandler(DataIntegrityViolationException.class)
  public ResponseEntity<ProblemDetail> handleDataIntegrity(DataIntegrityViolationException ex, HttpServletRequest request) {
    log.warn("409 Database Error at {}: {}", request.getRequestURI(), sanitizedCause(ex));
    return ErrorResponses.of(HttpStatus.CONFLICT, "database-error", "Database Error", "Operation violates database constraints", request);
  }

  private static String sanitizedCause(DataIntegrityViolationException ex) {
    Throwable root = ex.getRootCause();
    if (root instanceof SQLException sqlException) {
      return "sqlState=" + sqlException.getSQLState();
    }
    return "cause=" + (root != null ? root.getClass().getSimpleName() : ex.getClass().getSimpleName());
  }
}
