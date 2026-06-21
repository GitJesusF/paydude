package com.jesusf.paydude.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.jesusf.paydude.dto.transactions.TransactionResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Wiring tests for the three {@link ObjectMapper} beans defined in {@link IdempotencyConfig}.
 *
 * <p>Why this test exists: the idempotency refactor introduced three mappers with disjoint
 * responsibilities (HTTP responses, canonical hashing, response cache) and a subtle bug where
 * {@code canonicalJsonMapper} leaked into the HTTP pipeline because Spring Boot's
 * {@code @ConditionalOnMissingBean(ObjectMapper.class)} disables {@code JacksonAutoConfiguration}
 * when any other {@code ObjectMapper} bean is present. Without a regression test, the bug could
 * silently come back through any innocent refactor of the config class.
 *
 * <h2>Why {@code @SpringJUnitConfig} instead of {@code @SpringBootTest}</h2>
 * <p>{@code @SpringBootTest} would boot the whole application (Hibernate, Flyway, profiles,
 * Testcontainers) when only two {@code @Configuration} classes are under test. With
 * {@code @SpringJUnitConfig} a minimal context is assembled:
 * <ul>
 *   <li>{@link IdempotencyConfig}: the class under test (defines the three beans).</li>
 *   <li>{@link JacksonAutoConfiguration}: provides {@code Jackson2ObjectMapperBuilder}, without
 *       which the {@code @Primary objectMapper} cannot be constructed. Imported via
 *       {@code @ImportAutoConfiguration} because {@code @SpringJUnitConfig} disables auto-config
 *       by default.</li>
 * </ul>
 *
 * <h2>How the responseCacheMapper isolation is verified</h2>
 * <p>The bug to prevent: someone enables
 * {@code spring.jackson.write-dates-as-timestamps=true} in {@code application.properties} to save
 * bytes; without the explicit pinning on {@code responseCacheMapper}, old rows of
 * {@code idempotency_keys.response_body} (ISO-8601) and new rows (numeric epoch) would coexist in
 * the same column and replays would fail to deserialize.
 *
 * <p>Rather than simulating that scenario by toggling properties (fragile in a Spring slice
 * without {@code @ConfigurationProperties} loaded), the test asserts the bean's contract directly:
 * {@link SerializationFeature#WRITE_DATES_AS_TIMESTAMPS} must remain disabled on the
 * {@code responseCacheMapper}. As long as that flag stays OFF at construction time, no external
 * property can change it — the bean is built with {@code JsonMapper.builder()} rather than
 * {@code Jackson2ObjectMapperBuilder} (which would consume {@code spring.jackson.*}).
 */
@SpringJUnitConfig
@ContextConfiguration(classes = IdempotencyConfig.class)
@ImportAutoConfiguration(JacksonAutoConfiguration.class)
class IdempotencyConfigTest {

  // The whole ApplicationContext is injected to verify @Primary semantics via getBean. The three
  // mappers resolve by name: a bean rename breaks injection at test startup instead of leaving
  // stale @Qualifiers pointing at the old name in production.
  @Autowired private ApplicationContext context;

  @Autowired @Qualifier("objectMapper") private ObjectMapper primaryMapper;
  @Autowired @Qualifier("canonicalJsonMapper") private ObjectMapper canonicalMapper;
  @Autowired @Qualifier("responseCacheMapper") private ObjectMapper responseCacheMapper;

  @Nested
  @DisplayName("Bean wiring in the Spring context")
  class BeanWiring {

    @Test
    @DisplayName("The context exposes exactly three ObjectMappers, one per responsibility")
    void shouldExposeThreeDistinctObjectMappers() {
      // The strict count guards against an accidental fourth mapper slipping in undocumented.
      Map<String, ObjectMapper> mappers = context.getBeansOfType(ObjectMapper.class);

      assertEquals(3, mappers.size(),
          "Expected exactly 3 ObjectMappers: primary, canonical and responseCache");
      assertTrue(mappers.containsKey("objectMapper"));
      assertTrue(mappers.containsKey("canonicalJsonMapper"));
      assertTrue(mappers.containsKey("responseCacheMapper"));

      // Each @Bean must return an independent instance so their configurations cannot bleed.
      assertNotSame(primaryMapper, canonicalMapper);
      assertNotSame(primaryMapper, responseCacheMapper);
      assertNotSame(canonicalMapper, responseCacheMapper);
    }

    @Test
    @DisplayName("Resolving ObjectMapper without a qualifier returns @Primary, NOT canonical")
    void resolvingByTypeShouldReturnPrimaryNotCanonical() {
      // The historical bug: with only canonicalJsonMapper defined, JacksonAutoConfiguration's
      // @ConditionalOnMissingBean backed off and the canonical mapper became the implicit
      // primary — HTTP responses came out with alphabetized fields and stripped trailing zeros.
      // @Primary on objectMapper() is the fix; this test pins it.
      ObjectMapper resolved = context.getBean(ObjectMapper.class);
      assertSame(primaryMapper, resolved,
          "context.getBean(ObjectMapper.class) must return the @Primary bean");
      assertNotSame(canonicalMapper, resolved,
          "The canonical mapper must never be the @Primary — its rules are for hashing, not for HTTP");
    }
  }

  @Nested
  @DisplayName("responseCacheMapper is pinned; ignore spring.jackson.*")
  class CacheMapperPinning {

    // Two complementary checks: the configuration flag and the functional behaviour. Each
    // catches a regression class the other cannot.

    @Test
    @DisplayName("responseCacheMapper has WRITE_DATES_AS_TIMESTAMPS disabled in its configuration")
    void responseCacheMapperShouldHaveTimestampsFeatureDisabled() {
      // Checking the flag directly is robust to whatever lives in application.properties;
      // removing the .disable(...) line in IdempotencyConfig breaks this immediately.
      assertFalse(responseCacheMapper.isEnabled(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS),
          "responseCacheMapper must keep WRITE_DATES_AS_TIMESTAMPS=OFF for stable ISO-8601 storage");
    }

    @Test
    @DisplayName("responseCacheMapper serializes Instant as an ISO-8601 string, not as a number")
    void responseCacheMapperShouldSerializeDatesAsIso8601() throws JsonProcessingException {
      // Deliberately loose assertion (contains 'T') to avoid coupling to the exact ISO-8601
      // dialect JavaTimeModule emits — what matters is that it is not an epoch number.
      Instant now = Instant.parse("2026-04-27T10:30:00Z");
      String json = responseCacheMapper.writeValueAsString(new DateHolder(now));

      assertTrue(json.contains("2026-04-27T"),
          "responseCacheMapper must emit ISO-8601 (with 'T'), never epoch numbers. JSON: " + json);
    }

    /**
     * Minimal DTO scoped to this test — only an {@link Instant} is needed to isolate Jackson's
     * date-handling behavior. Declared as a static nested record so production code is not
     * polluted with test-only types.
     */
    record DateHolder(Instant date) { }
  }

  @Nested
  @DisplayName("responseCacheMapper round-trip end-to-end with TransactionResponse")
  class CacheMapperRoundTrip {

    @Test
    @DisplayName("Serializing and deserializing a TransactionResponse returns an equivalent object")
    void shouldRoundTripTransactionResponse() throws JsonProcessingException {
      // Simulates the production flow: serialize after a successful transfer, persist in
      // idempotency_keys.response_body, re-read on retry, deserialize. Real Jackson, not a
      // mock — round-trip equivalence only means something with real bytes. TransactionResponse
      // is a record, so equals() compares all nine fields structurally.
      TransactionResponse original = new TransactionResponse(
          42L,
          "SENT",
          new BigDecimal("250.50"),
          "USD",
          "Jane Doe",
          "ACC-002",
          "rent — april",
          "COMPLETED",
          Instant.parse("2026-04-27T10:30:00Z")
      );

      String json = responseCacheMapper.writeValueAsString(original);
      TransactionResponse parsed = responseCacheMapper.readValue(json, TransactionResponse.class);

      assertEquals(original, parsed,
          "The deserialized response must be equivalent to the original. Intermediate JSON: " + json);
    }
  }
}
