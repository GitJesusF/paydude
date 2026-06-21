package com.jesusf.paydude.security.ratelimit;

import jakarta.servlet.http.HttpServletResponse;

/**
 * Writes the IETF {@code RateLimit} / {@code RateLimit-Policy} response header fields
 * ({@code draft-ietf-httpapi-ratelimit-headers}) so a client can slow down <i>before</i> it is
 * throttled, instead of discovering the limit only when it hits a 429.
 *
 * <p>Both fields use HTTP Structured Fields syntax, keyed by a quoted policy name so the dynamic
 * state correlates with its static policy:
 *
 * <pre>
 *   RateLimit-Policy: "login";q=20;w=60     quota q tokens per window w seconds   (static)
 *   RateLimit:        "login";r=19;t=42     r tokens remaining, resets in t sec   (dynamic)
 * </pre>
 *
 * <p>The de-facto predecessor was the {@code X-RateLimit-Limit/Remaining/Reset} triple popularised
 * by GitHub and Twitter; the IETF draft supersedes it with these structured fields. {@code
 * Retry-After} (RFC 6585) still rides on the 429 for clients that understand only the simpler
 * back-off hint, so the two are complementary rather than redundant.
 */
final class RateLimitHeaders {

  static final String RATE_LIMIT = "RateLimit";
  static final String RATE_LIMIT_POLICY = "RateLimit-Policy";

  private RateLimitHeaders() {}

  /**
   * Sets the {@code RateLimit} and {@code RateLimit-Policy} fields for one policy on the response.
   *
   * @param response      the servlet response
   * @param policyName    the policy partition name (becomes the quoted structured-field key)
   * @param quota         tokens granted per window — {@code q}
   * @param windowSeconds window length in seconds — {@code w}
   * @param remaining     tokens left after this request — {@code r} (clamped to ≥ 0)
   * @param resetSeconds  seconds until the window resets — {@code t} (clamped to ≥ 0)
   */
  static void write(HttpServletResponse response, String policyName, long quota, long windowSeconds, long remaining, long resetSeconds) {
    response.setHeader(RATE_LIMIT_POLICY, "\"" + policyName + "\";q=" + quota + ";w=" + windowSeconds);
    response.setHeader(RATE_LIMIT, "\"" + policyName + "\";r=" + Math.max(remaining, 0) + ";t=" + Math.max(resetSeconds, 0));
  }
}
