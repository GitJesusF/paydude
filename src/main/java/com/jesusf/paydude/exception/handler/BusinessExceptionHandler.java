package com.jesusf.paydude.exception.handler;

import com.jesusf.paydude.exception.BusinessException;
import com.jesusf.paydude.exception.ResourceNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Domain-rule violations: missing resources and business invariants enforced by services. */
@Slf4j
@Order(30)
@RestControllerAdvice
public class BusinessExceptionHandler {

  @ExceptionHandler(ResourceNotFoundException.class)
  public ResponseEntity<ProblemDetail> handleNotFound(ResourceNotFoundException ex, HttpServletRequest request) {
    log.warn("404 Not Found at {}: {}", request.getRequestURI(), ex.getMessage());
    return ErrorResponses.of(HttpStatus.NOT_FOUND, "not-found", "Not Found", ex.getMessage(), request);
  }

  @ExceptionHandler(BusinessException.class)
  public ResponseEntity<ProblemDetail> handleBusiness(BusinessException ex, HttpServletRequest request) {
    log.warn("409 Business Conflict at {}: {}", request.getRequestURI(), ex.getMessage());
    return ErrorResponses.of(HttpStatus.CONFLICT, "business-conflict", "Business Conflict", ex.getMessage(), request);
  }
}