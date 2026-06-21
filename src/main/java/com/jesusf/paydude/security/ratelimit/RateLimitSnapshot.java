package com.jesusf.paydude.security.ratelimit;

/**
 * Everything the IETF {@code RateLimit} / {@code RateLimit-Policy} headers need for one bucket,
 * bundled so the filter can render them without reaching for {@code SecurityProperties} or the
 * bucket4j {@code ConsumptionProbe} type. Carrying the static policy ({@code quota}/{@code window})
 * alongside the dynamic state keeps the filter a thin, dependency-light choke point — important
 * because it is component-scanned into every {@code @WebMvcTest} slice.
 *
 * @param allowed         whether the token was consumed (the request is within the limit)
 * @param quota           tokens granted per window — the {@code RateLimit-Policy} {@code q}
 * @param windowSeconds   window length in seconds — the {@code RateLimit-Policy} {@code w}
 * @param remainingTokens tokens left in the window after this attempt — the {@code RateLimit} {@code r} (≥ 0)
 * @param secondsToReset  seconds until the bucket refills to capacity — the {@code RateLimit} {@code t} (≥ 0)
 */
public record RateLimitSnapshot(
    boolean allowed,
    long quota,
    long windowSeconds,
    long remainingTokens,
    long secondsToReset
) {}
