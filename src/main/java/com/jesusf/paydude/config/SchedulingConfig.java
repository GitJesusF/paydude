package com.jesusf.paydude.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Enables Spring's annotation-driven scheduling so {@code @Scheduled} methods — currently the
 * expired-row cleanup job in {@code com.jesusf.paydude.job} — fire on their cron.
 *
 * <p>Isolated in its own {@code @Configuration} for the same reason {@code @EnableJpaAuditing} lives
 * on {@code JpaConfig} rather than {@code Application}: a {@code @WebMvcTest} slice loads neither, so
 * the web-layer tests never spin up a {@code TaskScheduler} or fire a background job. The full
 * {@code @SpringBootTest} context does load this, but the job's cron
 * ({@code application.cleanup.cron} — daily at 03:00 UTC by default, set to the disabled marker
 * {@code "-"} in the {@code test} profile) never fires within a test run.
 */
@Configuration
@EnableScheduling
public class SchedulingConfig {
}
