package com.jesusf.paydude.security;

import com.jesusf.paydude.support.TestcontainersConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end integration test for the HTTP-standards layer of the security chain.
 *
 * <p>Boots the full Spring context so the real {@code SecurityConfig} filter chain runs, and
 * pins contracts that unit tests with {@code addFilters = false} cannot reach:
 * <ol>
 *   <li><b>RFC 6750</b> — a 401 carries a {@code WWW-Authenticate: Bearer} challenge; if the
 *       caller presented a token, the challenge narrows to {@code error="invalid_token"}.</li>
 *   <li><b>OWASP Secure Headers</b> — every response carries {@code X-Content-Type-Options},
 *       {@code Referrer-Policy} and {@code Content-Security-Policy}.</li>
 *   <li><b>RFC 9111</b> — responses are non-cacheable ({@code Cache-Control: no-store}), so no
 *       proxy or browser retains account data.</li>
 *   <li><b>CORS</b> — a preflight from an allowed origin is approved with the matching
 *       {@code Access-Control-Allow-Origin}; a preflight from an unknown origin is rejected and
 *       carries no allow-origin header.</li>
 *   <li><b>RFC 7617</b> — the Actuator admin tier (exercised here via {@code /actuator/metrics};
 *       same chain gates {@code /actuator/prometheus} in prod) is guarded by HTTP Basic: anonymous
 *       gets a 401 with a {@code WWW-Authenticate: Basic} challenge, the scraper credential gets a
 *       200, and {@code /actuator/health} stays anonymous.</li>
 * </ol>
 *
 * <p>HSTS is intentionally <i>not</i> asserted: Spring Security emits it only on HTTPS requests,
 * and MockMvc drives the chain over plain HTTP — the absence of the header here is correct
 * behavior, not a gap.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class HttpStandardsIT {

  @Autowired
  private MockMvc mockMvc;

  // Any protected endpoint exercises the chain; without a token it 401s — the exact moment
  // CustomSecurityExceptionHandler must have written the WWW-Authenticate challenge.
  private static final String PROTECTED_ENDPOINT = "/v1/accounts/me";

  // The `test` profile inherits application.cors.allowed-origins from application.properties.
  private static final String ALLOWED_ORIGIN = "http://localhost:3000";
  private static final String DISALLOWED_ORIGIN = "http://evil.example.com";

  // Admin tier stand-in: the test context falls back to SimpleMeterRegistry and does not wire
  // the Prometheus endpoint, but /actuator/metrics is gated by the SAME actuatorSecurityFilterChain
  // that gates /actuator/prometheus in prod. /actuator/health stays anonymous.
  private static final String ADMIN_ACTUATOR_ENDPOINT = "/actuator/metrics";
  private static final String PUBLIC_ACTUATOR_ENDPOINT = "/actuator/health";
  // Scraper credential: username default from application.properties, password from
  // application-test.properties — the technical account SecurityConfig loads into the actuator
  // chain's InMemoryUserDetailsManager.
  private static final String SCRAPER_USER = "prometheus";
  private static final String SCRAPER_PASSWORD = "test-actuator-secret";

  @Test
  @DisplayName("RFC 6750 - A 401 with no token carries a bare Bearer challenge")
  void shouldEmitBareBearerChallengeWhenNoToken() throws Exception {
    // No credential was presented, so there is nothing to report as invalid — the bare scheme
    // just tells the client how to authenticate.
    mockMvc.perform(get(PROTECTED_ENDPOINT))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"));
  }

  @Test
  @DisplayName("API auth surface - unlisted /v1/auth/** routes fail closed")
  void shouldRequireAuthenticationForUnlistedAuthRoutes() throws Exception {
    // The public auth list is intentionally exact (register/login/refresh/logout). A future route
    // added under /auth must opt in to permitAll explicitly; otherwise it inherits authenticated().
    mockMvc.perform(get("/v1/auth/sessions"))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"));
  }

  @Test
  @DisplayName("RFC 6750 - A 401 with a bad token narrows the challenge to invalid_token")
  void shouldEmitInvalidTokenChallengeWhenTokenPresent() throws Exception {
    // RFC 6750 §3: when a token was presented and failed, error="invalid_token" lets the client
    // distinguish "credential missing" from "credential no longer works, re-authenticate".
    mockMvc.perform(get(PROTECTED_ENDPOINT)
            .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-real-jwt"))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\""));
  }

  @Test
  @DisplayName("OWASP Secure Headers + RFC 9111 - Every response carries the defensive header baseline")
  void shouldEmitSecurityHeadersOnEveryResponse() throws Exception {
    // HeaderWriterFilter runs early in the chain, so the headers appear even on a 401 — no
    // authenticated request needed.
    mockMvc.perform(get(PROTECTED_ENDPOINT))
        .andExpect(header().string("X-Content-Type-Options", "nosniff"))
        .andExpect(header().string("Referrer-Policy", "no-referrer"))
        .andExpect(header().string("Content-Security-Policy", "frame-ancestors 'none'"))
        // Spring Security emits `no-cache, no-store, max-age=0, must-revalidate`; assert only
        // the token that matters.
        .andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")));
  }

  @Test
  @DisplayName("CORS - A preflight from an allowed origin is approved")
  void shouldApproveCorsPreflightFromAllowedOrigin() throws Exception {
    // Preflights carry no credentials and must not 401; Spring Security answers them before
    // authorization and reflects an allow-listed origin back.
    mockMvc.perform(options(PROTECTED_ENDPOINT)
            .header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN)
            .header("Access-Control-Request-Method", "GET"))
        .andExpect(status().isOk())
        .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN));
  }

  @Test
  @DisplayName("CORS - A preflight from an unknown origin is rejected with no allow-origin header")
  void shouldRejectCorsPreflightFromDisallowedOrigin() throws Exception {
    // 403 with no Access-Control-Allow-Origin → the browser blocks the real request.
    mockMvc.perform(options(PROTECTED_ENDPOINT)
            .header(HttpHeaders.ORIGIN, DISALLOWED_ORIGIN)
            .header("Access-Control-Request-Method", "GET"))
        .andExpect(status().isForbidden())
        .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
  }

  @Test
  @DisplayName("RFC 7617 - The Actuator admin tier challenges anonymous callers with Basic")
  void shouldChallengeAnonymousActuatorAdminWithBasic() throws Exception {
    // The Basic challenge — as opposed to the Bearer challenge the API chain emits — is the
    // proof that the two SecurityFilterChains coexist correctly.
    mockMvc.perform(get(ADMIN_ACTUATOR_ENDPOINT))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("Basic")));
  }

  @Test
  @DisplayName("RFC 7617 - The Actuator admin tier admits the scraper credential")
  void shouldAdmitActuatorAdminWithScraperCredential() throws Exception {
    // Proves the in-memory scraper account holds ROLE_ADMIN and its password matches the encoder.
    mockMvc.perform(get(ADMIN_ACTUATOR_ENDPOINT)
            .with(httpBasic(SCRAPER_USER, SCRAPER_PASSWORD)))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("RFC 7617 - The public Actuator tier (health) stays anonymous")
  void shouldKeepActuatorHealthAnonymous() throws Exception {
    mockMvc.perform(get(PUBLIC_ACTUATOR_ENDPOINT))
        .andExpect(status().isOk());
  }

  @Test
  @DisplayName("Actuator probe tier - a stale Bearer header must not break the anonymous health check")
  void shouldKeepActuatorHealthAnonymousEvenWithStaleBearerToken() throws Exception {
    // Pins SecurityConfig's FilterRegistrationBean(enabled=false): as a @Component, Boot would
    // otherwise register JwtAuthenticationFilter a second time as a plain container filter —
    // outside both security chains — which would run after the actuator chain and 401 a request
    // the public tier had already allowed.
    mockMvc.perform(get(PUBLIC_ACTUATOR_ENDPOINT)
            .header(HttpHeaders.AUTHORIZATION, "Bearer stale-or-garbage-token"))
        .andExpect(status().isOk());
  }
}
