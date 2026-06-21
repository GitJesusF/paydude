package com.jesusf.paydude.exception.handler;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;

import java.net.URI;
import java.time.Instant;
import java.util.Map;

/**
 * Central factory for RFC 9457 {@link ProblemDetail} responses.
 *
 * <p>RFC 9457 (which obsoletes RFC 7807) defines a single, standard envelope for HTTP error
 * bodies: {@code type}, {@code title}, {@code status}, {@code detail}, {@code instance}. Spring
 * Framework 6 / Spring Boot 3 ship a first-class {@link ProblemDetail} record that serializes to
 * this exact shape and triggers the {@code application/problem+json} content type automatically.
 *
 * <p>This helper centralises three decisions so the @{@code RestControllerAdvice} classes never
 * have to think about them:
 *
 * <ol>
 *   <li><b>The {@code type} URI is mandatory and stable.</b> The default of {@code about:blank}
 *       (used when {@code setType} is not called) collapses all problem types onto the HTTP
 *       status code, which is useless when two 409s map to different domain conditions
 *       ({@code BusinessException} vs {@code OptimisticLockingFailureException}). We assign a
 *       relative {@code /problems/<slug>} URI per category — a relative URI is RFC-legal and
 *       avoids hard-coding a hostname into responses. A client that needs documentation can
 *       resolve the URI against the base URL of the API.</li>
 *
 *   <li><b>{@code instance} is the request URI.</b> RFC 9457 §3.1.5 defines instance as "a URI
 *       reference that identifies the specific occurrence of the problem"; the request path is
 *       the canonical choice and matches the previous {@code path} field one-to-one.</li>
 *
 *   <li><b>Two extension fields ride alongside the standard ones</b> via
 *       {@link ProblemDetail#setProperty(String, Object)}, which Jackson exposes as top-level
 *       JSON via {@code @JsonAnyGetter}:
 *       <ul>
 *         <li>{@code timestamp} — server clock when the error was produced. Useful when
 *             correlating logs after the fact.</li>
 *         <li>{@code errors} (only on validation failures) — map of {@code field → message} so
 *             clients don't have to free-text parse {@code detail}.</li>
 *       </ul>
 *       Extension fields are explicitly endorsed by RFC 9457 §3.2 as the way to convey
 *       domain-specific information without polluting the standard fields.</li>
 * </ol>
 *
 * <p>Why a thin helper instead of inlining {@code ProblemDetail.forStatusAndDetail(...)} at every
 * call-site: the per-concern handlers shouldn't need to know about the type URI registry or the
 * extension-field naming convention. Centralising those means a future change (new field, new
 * URI scheme) is a single-file edit.
 */
final class ErrorResponses {

  private ErrorResponses() {}

  /**
   * Builds a {@link ProblemDetail} error response.
   *
   * @param status  the HTTP status
   * @param type    the problem-type slug; becomes the relative {@code /problems/<type>} URI
   * @param title   the short, human-readable problem title
   * @param detail  the occurrence-specific detail message
   * @param request the current request; its URI becomes the {@code instance}
   * @return the body wrapped in a {@link ResponseEntity} at the given status
   */
  static ResponseEntity<ProblemDetail> of(
      HttpStatus status, String type, String title, String detail, HttpServletRequest request
  ) {
    return ResponseEntity.status(status).body(buildProblem(status, type, title, detail, request, null));
  }

  /**
   * Builds a {@link ProblemDetail} error response carrying a field-level {@code errors} map —
   * the form used for validation failures.
   *
   * @param status  the HTTP status
   * @param type    the problem-type slug; becomes the relative {@code /problems/<type>} URI
   * @param title   the short, human-readable problem title
   * @param detail  the occurrence-specific detail message
   * @param request the current request; its URI becomes the {@code instance}
   * @param errors  map of {@code field → message}, surfaced as the {@code errors} extension field
   * @return the body wrapped in a {@link ResponseEntity} at the given status
   */
  static ResponseEntity<ProblemDetail> of(
      HttpStatus status, String type, String title, String detail, HttpServletRequest request,
      Map<String, String> errors
  ) {
    return ResponseEntity.status(status).body(buildProblem(status, type, title, detail, request, errors));
  }

  /**
   * Builds the {@link ProblemDetail} body without wrapping it in a {@link ResponseEntity} — used by
   * handlers that need to attach extra response headers (e.g. {@code Retry-After}, {@code Allow})
   * and therefore have to call {@code ResponseEntity.status(...).header(...).body(...)} themselves.
   */
  static ProblemDetail buildProblem(
      HttpStatus status, String type, String title, String detail, HttpServletRequest request,
      Map<String, String> errors
  ) {
    ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
    problem.setType(URI.create("/problems/" + type));
    problem.setTitle(title);
    problem.setInstance(URI.create(request.getRequestURI()));
    problem.setProperty("timestamp", Instant.now());
    if (errors != null && !errors.isEmpty()) {
      problem.setProperty("errors", errors);
    }
    return problem;
  }
}