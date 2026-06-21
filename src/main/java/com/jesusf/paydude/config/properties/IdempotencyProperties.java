package com.jesusf.paydude.config.properties;

import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Type-safe binding for every {@code application.idempotency.*} property.
 *
 * <p>The TTL applied to a freshly reserved {@link com.jesusf.paydude.entity.IdempotencyKey} used
 * to live as a hard-coded {@code Instant.now().plus(24, ChronoUnit.DAYS)} inside
 * {@code IdempotencyKeyServiceImpl}. Externalizing it gives operators a knob to tighten retention
 * (e.g. during a compliance review that requires shorter request-data persistence) without a
 * redeploy, and feeds the scheduled cleanup job ({@code ExpiredDataCleanupJob}): a row's
 * {@code expiresAt} is {@code insertTime + keyTtl}, and the job deletes rows whose {@code expiresAt}
 * has passed — so a key is never pruned while still inside its valid retry window.
 *
 * @param keyTtl How long a reserved key remains queryable before the cleanup job is allowed to
 *               purge it. Spring Boot parses {@link Duration} from ISO-8601 ({@code "PT24H"}) or
 *               a friendlier format ({@code "24h"}, {@code "7d"}) — see
 *               {@code spring.boot.convert.DurationStyle}.
 */
@ConfigurationProperties(prefix = "application.idempotency")
@Validated
public record IdempotencyProperties(
    @NotNull @DurationMin(seconds = 60) Duration keyTtl
) {}
