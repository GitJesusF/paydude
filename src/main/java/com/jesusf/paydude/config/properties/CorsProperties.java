package com.jesusf.paydude.config.properties;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.PositiveOrZero;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * Type-safe binding for every {@code application.cors.*} property.
 *
 * <p>CORS (Cross-Origin Resource Sharing) is the browser-enforced protocol that decides which web
 * origins may call this API from JavaScript. Without it, a browser blocks every cross-origin
 * {@code fetch} to PayDude — so any first-party SPA on a different host (the common case in
 * development: a frontend on {@code localhost:3000} talking to this API on {@code :8090}) cannot
 * consume the API at all. The {@code allowed-methods}, {@code allowed-headers} and
 * {@code exposed-headers} below follow directly from the API's own design and are stable across
 * environments; only {@code allowed-origins} varies per deployment, which is why the prod profile
 * overrides just that key from an environment variable.
 *
 * <p><b>Why externalised instead of hard-coded.</b> The same reason the rate-limit thresholds and
 * the JWT settings are externalised: the allowed-origin list is an operational value that differs
 * between every environment and must never require a recompile to change. Binding it through a
 * {@code @Validated} record makes a missing or empty list fail fast at boot rather than surface
 * later as a silently broken frontend.
 *
 * <p><b>Credentials are intentionally not allowed.</b> PayDude authenticates with a Bearer token
 * carried in the {@code Authorization} header — which the JS client sets explicitly — not with
 * cookies. {@code SecurityConfig} therefore configures {@code allowCredentials(false)}: there is
 * no ambient credential for the browser to attach, so enabling it would only widen the surface
 * for no functional gain.
 *
 * @param allowedOrigins  Exact web origins permitted to call the API (scheme + host + port). No
 *                        wildcards — an explicit allow-list is the defensible choice for an API
 *                        that moves money. Prod supplies this via {@code CORS_ALLOWED_ORIGINS}.
 * @param allowedMethods  HTTP methods a cross-origin caller may use. Mirrors the verbs the
 *                        controllers actually expose, plus {@code OPTIONS} for the preflight.
 * @param allowedHeaders  Request headers a cross-origin caller may send — notably
 *                        {@code Authorization} and {@code Idempotency-Key} (without which the
 *                        protected and idempotent endpoints are unreachable) plus
 *                        {@code traceparent}, so a browser client can propagate a W3C trace into
 *                        the API.
 * @param exposedHeaders  Response headers the browser is allowed to read back — {@code Retry-After}
 *                        (so a throttled client knows when to retry).
 * @param maxAge          Seconds the browser may cache a preflight result, avoiding an {@code OPTIONS}
 *                        round-trip before every actual request.
 */
@ConfigurationProperties(prefix = "application.cors")
@Validated
public record CorsProperties(
    @NotEmpty List<String> allowedOrigins,
    @NotEmpty List<String> allowedMethods,
    @NotEmpty List<String> allowedHeaders,
    List<String> exposedHeaders,
    @PositiveOrZero long maxAge
) {}