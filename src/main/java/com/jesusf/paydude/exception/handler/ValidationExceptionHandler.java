package com.jesusf.paydude.exception.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Handles HTTP-protocol and request-shape errors: malformed JSON, failed bean validation,
 * missing required headers, wrong HTTP verb or media type. All map to client-side 4xx
 * statuses and log at WARN — these are client misuses, not server faults.
 */
@Slf4j
@Order(10)
@RestControllerAdvice
public class ValidationExceptionHandler {

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ProblemDetail> handleBeanValidation(MethodArgumentNotValidException ex, HttpServletRequest request) {
    Map<String, String> errors = new HashMap<>();
    for (FieldError error : ex.getBindingResult().getFieldErrors()) {
      errors.put(error.getField(), error.getDefaultMessage());
    }
    log.warn("400 Validation Error at {}: {} field(s) failed", request.getRequestURI(), errors.size());
    return ErrorResponses.of(HttpStatus.BAD_REQUEST, "validation-error", "Validation Error", "Invalid input data", request, errors);
  }

  @ExceptionHandler(ConstraintViolationException.class)
  public ResponseEntity<ProblemDetail> handleConstraintViolation(ConstraintViolationException ex, HttpServletRequest request) {
    Map<String, String> errors = new HashMap<>();
    for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
      String path = violation.getPropertyPath().toString();
      String field = path.contains(".") ? path.substring(path.lastIndexOf('.') + 1) : path;
      errors.put(field, violation.getMessage());
    }
    log.warn("400 Validation Error at {}: {} parameter(s) failed", request.getRequestURI(), errors.size());
    return ErrorResponses.of(HttpStatus.BAD_REQUEST, "validation-error", "Validation Error", "Invalid request parameters", request, errors);
  }

  @ExceptionHandler(MissingRequestHeaderException.class)
  public ResponseEntity<ProblemDetail> handleMissingHeader(MissingRequestHeaderException ex, HttpServletRequest request) {
    log.warn("400 Missing Header at {}: {}", request.getRequestURI(), ex.getHeaderName());
    return ErrorResponses.of(HttpStatus.BAD_REQUEST, "missing-header", "Missing Header", ex.getMessage(), request);
  }

  /**
   * Catches structural request errors that fire before {@code @Valid} runs:
   * <ul>
   *   <li>Malformed or unparseable JSON.</li>
   *   <li>{@code IllegalArgumentException} thrown from a record's compact constructor when a
   *       cross-field invariant fails (e.g. {@code TransferRequest} rejecting source == target).</li>
   * </ul>
   *
   * <p>Only the compact-constructor case surfaces its message verbatim: those strings are written
   * by this codebase for clients. Everything else (Jackson parse/mapping errors) collapses into a
   * generic detail — the raw messages embed fully-qualified class names, parser positions and the
   * offending input, which is internals leakage, not actionable client feedback. The exact cause
   * still goes to the WARN log line for debugging.
   */
  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<ProblemDetail> handleUnreadableMessage(HttpMessageNotReadableException ex, HttpServletRequest request) {
    Throwable cause = ex.getMostSpecificCause();
    // Exact-class check on purpose: subclasses like NumberFormatException are Jackson/JDK noise
    // that echoes input, not a domain invariant message authored for the client.
    String detail = (cause != null && cause.getClass() == IllegalArgumentException.class)
        ? cause.getMessage()
        : "Request body is malformed or could not be parsed";
    log.warn("400 Malformed Request at {}: {}", request.getRequestURI(),
        cause != null ? cause.getMessage() : ex.getMessage());
    return ErrorResponses.of(HttpStatus.BAD_REQUEST, "malformed-request", "Malformed Request", detail, request);
  }

  /**
   * RFC 9110 §15.5.6 mandates the {@code Allow} header on every 405 so automated clients can
   * recover by switching verbs without parsing the body. The ProblemDetail body is built via
   * the shared helper, then wrapped manually so the {@code Allow} header can be attached.
   */
  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  public ResponseEntity<ProblemDetail> handleMethodNotSupported(HttpRequestMethodNotSupportedException ex, HttpServletRequest request) {
    log.warn("405 Method Not Allowed at {}: tried {}, supported {}",
        request.getRequestURI(), ex.getMethod(), ex.getSupportedHttpMethods());

    ProblemDetail body = ErrorResponses.buildProblem(
        HttpStatus.METHOD_NOT_ALLOWED,
        "method-not-allowed",
        "Method Not Allowed",
        "HTTP method '" + ex.getMethod() + "' is not supported on this endpoint",
        request,
        null
    );

    ResponseEntity.BodyBuilder builder = ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED);
    if (ex.getSupportedHttpMethods() != null && !ex.getSupportedHttpMethods().isEmpty()) {
      String allow = ex.getSupportedHttpMethods().stream()
          .map(HttpMethod::name)
          .collect(Collectors.joining(", "));
      builder.header(HttpHeaders.ALLOW, allow);
    }
    return builder.body(body);
  }

  @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
  public ResponseEntity<ProblemDetail> handleMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex, HttpServletRequest request) {
    log.warn("415 Unsupported Media Type at {}: contentType={}",
        request.getRequestURI(), ex.getContentType());
    return ErrorResponses.of(
        HttpStatus.UNSUPPORTED_MEDIA_TYPE,
        "unsupported-media-type",
        "Unsupported Media Type",
        "Content-Type '" + ex.getContentType() + "' is not supported. Use application/json.",
        request
    );
  }

}