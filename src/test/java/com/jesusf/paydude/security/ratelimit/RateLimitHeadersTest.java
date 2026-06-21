package com.jesusf.paydude.security.ratelimit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for {@link RateLimitHeaders}.
 *
 * <p>Pins the exact wire format of the IETF {@code RateLimit} / {@code RateLimit-Policy} structured
 * fields — a client (or an OpenAPI consumer) parses these byte-for-byte, so a stray space or a
 * dropped quote would silently break interoperability.
 */
class RateLimitHeadersTest {

  @Test
  @DisplayName("writes IETF structured-field RateLimit and RateLimit-Policy headers")
  void writesStructuredFields() {
    MockHttpServletResponse response = new MockHttpServletResponse();

    RateLimitHeaders.write(response, "login", 20, 60, 19, 42);

    assertEquals("\"login\";q=20;w=60", response.getHeader("RateLimit-Policy"),
        "policy field carries the static quota (q) and window (w)");
    assertEquals("\"login\";r=19;t=42", response.getHeader("RateLimit"),
        "ratelimit field carries the dynamic remaining (r) and reset (t)");
  }

  @Test
  @DisplayName("clamps negative remaining and reset to zero")
  void clampsNegativeValues() {
    // getNanosToWaitForReset can momentarily round to a tiny negative under clock skew; the
    // structured-field integers must never go below zero.
    MockHttpServletResponse response = new MockHttpServletResponse();

    RateLimitHeaders.write(response, "write", 30, 60, -5, -1);

    assertEquals("\"write\";r=0;t=0", response.getHeader("RateLimit"));
    assertEquals("\"write\";q=30;w=60", response.getHeader("RateLimit-Policy"));
  }
}
