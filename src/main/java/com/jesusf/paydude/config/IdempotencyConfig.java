package com.jesusf.paydude.config;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.jesusf.paydude.config.mixin.AccountOperationRequestCanonicalMixin;
import com.jesusf.paydude.config.mixin.TransferRequestCanonicalMixin;
import com.jesusf.paydude.dto.idempotent.AccountOperationRequest;
import com.jesusf.paydude.dto.idempotent.TransferRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.io.IOException;
import java.math.BigDecimal;

/**
 * Jackson wiring for the idempotency layer.
 *
 * <p>Idempotent request deduplication needs two things that the application's HTTP
 * {@link ObjectMapper} cannot safely provide: a <em>canonical</em> serialization for hashing
 * requests, and a <em>format-frozen</em> serialization for the durable response cache. Reusing
 * the HTTP mapper for either would couple a storage/hashing concern to API-response formatting.
 *
 * <p>This class therefore declares three distinct mappers — each documented on its own
 * {@code @Bean} method below:
 * <ul>
 *   <li>{@code objectMapper} — the {@code @Primary} HTTP mapper, declared explicitly so the
 *       canonical mapper cannot accidentally take that role.</li>
 *   <li>{@code canonicalJsonMapper} — deterministic output for SHA-256 request fingerprints.</li>
 *   <li>{@code responseCacheMapper} — a pinned format for the cached response body.</li>
 * </ul>
 */
@Configuration
public class IdempotencyConfig {

  /**
   * Spring Boot's {@code JacksonAutoConfiguration} only creates its default {@link ObjectMapper}
   * when no other {@code ObjectMapper} bean exists ({@code @ConditionalOnMissingBean}). The
   * {@link #canonicalJsonMapper()} below would otherwise satisfy that condition and silently
   * become the application's primary mapper — including the one wired into Spring MVC's HTTP
   * message converters. That would push the canonical-form rules (sorted fields, stripped
   * BigDecimal trailing zeros) into every JSON response we emit, which is wrong: those rules
   * exist to make hashes deterministic, not to reshape API responses.
   *
   * <p>Defining the primary mapper explicitly here disables that side effect. We use
   * {@link Jackson2ObjectMapperBuilder} (rather than {@code new ObjectMapper()}) so Spring Boot's
   * auto-registered modules — most importantly {@code JavaTimeModule} for ISO-8601 timestamps —
   * are still applied, and any {@code spring.jackson.*} property in {@code application.properties}
   * keeps working.
   */
  @Bean
  @Primary
  public ObjectMapper objectMapper(Jackson2ObjectMapperBuilder builder) {
    return builder.build();
  }

  /**
   * Stable, pinned {@link ObjectMapper} used by the idempotency layer to serialize the
   * {@code TransactionResponse} into {@code idempotency_keys.response_body} and to deserialize
   * it back on a replay. Independent from both the primary mapper and {@link
   * #canonicalJsonMapper()}.
   *
   * <p><b>Why a dedicated mapper.</b> The cached body is durable: a row written today may be
   * replayed weeks later, possibly across a deployment that flipped some {@code spring.jackson.*}
   * property (e.g. {@code write-dates-as-timestamps=true}). If the cache used the primary
   * mapper, that single property change would silently produce two formats coexisting in the
   * same column — old rows as ISO-8601 strings, new rows as numeric epoch millis — and replays
   * would deserialize differently depending on when the row was written. Pinning the
   * configuration on a separate bean isolates the storage format from any future tweak to
   * HTTP serialization.
   *
   * <p><b>Why not reuse {@code canonicalJsonMapper}.</b> The canonical mapper is built for
   * <i>hashing requests</i>: it sorts fields alphabetically and strips trailing zeros from
   * {@link BigDecimal} so semantically equal payloads collapse to the same digest. Those
   * transformations are wrong for caching responses: a replay must echo the original wire
   * format ({@code 100.0000}, original field order), not a normalized one.
   *
   * <p><b>What is pinned.</b> {@code WRITE_DATES_AS_TIMESTAMPS} is explicitly disabled so
   * timestamps are always serialized as ISO-8601 strings via {@link JavaTimeModule}, regardless
   * of any Spring Boot property override. The mapper is built from {@code JsonMapper.builder()}
   * (not {@code Jackson2ObjectMapperBuilder}) so it does not pick up {@code spring.jackson.*}
   * customizations — that's the whole point.
   *
   * <p><b>Residual scope.</b> This bean governs cache storage only. The bytes the client
   * receives on a replay still flow through Spring MVC's primary mapper at the wire layer; a
   * truly format-frozen replay would require returning the cached string verbatim through the
   * message-converter chain, which is out of scope here.
   */
  @Bean
  public ObjectMapper responseCacheMapper() {
    return JsonMapper.builder()
        .addModule(new JavaTimeModule())
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
        .build();
  }

  /**
   * A dedicated {@link ObjectMapper} that serializes objects in a <b>canonical</b> form, i.e. so
   * that two semantically equal payloads always produce the exact same byte-for-byte JSON. Used by
   * {@code IdempotencyKeyServiceImpl} to hash incoming request DTOs into the {@code request_hash}
   * column, where stability across retries is the whole point of the column existing.
   *
   * <p>Why a separate mapper instead of reusing Spring's default one: the default mapper is tuned
   * for HTTP responses (pretty-print toggles, ordering left to the JVM, etc.) and any change to
   * its config — even a harmless one — would silently invalidate every {@code requestHash} stored
   * in {@code idempotency_keys}. Pinning the canonical settings on a separate bean isolates the
   * hashing pipeline from any future tweak to HTTP serialization.
   *
   * <p><b>Two layers of canonicalization, by design:</b>
   *
   * <ol>
   *   <li><b>Cross-DTO rules</b> — apply uniformly to every {@code IdempotentRequest}:
   *     <ul>
   *       <li>{@code SORT_PROPERTIES_ALPHABETICALLY}: writes object fields in a deterministic
   *           order so reordering fields in a DTO record (or relying on JVM iteration order)
   *           cannot change the resulting JSON, and therefore cannot change the hash.</li>
   *       <li>Custom {@link BigDecimal} serializer: strips trailing zeros and emits a plain
   *           decimal (no scientific notation). Guarantees {@code "100"}, {@code "100.0"} and
   *           {@code "100.00"} hash to the same value. Adding new DTOs with monetary amounts
   *           inherits the behavior automatically.</li>
   *     </ul>
   *   </li>
   *   <li><b>Per-DTO rules</b> — registered through Jackson <i>mix-ins</i>, one per DTO that
   *     needs to opt out specific fields from hashing. Mix-ins live in this package
   *     ({@code TransferRequestCanonicalMixin}, etc.) so the DTOs themselves stay free of
   *     infrastructure annotations — the hashing rules are co-located with the mapper, not
   *     scattered through the domain model. To exclude a field for a new DTO, create a mix-in
   *     interface declaring the accessor with {@code @JsonIgnore} and register it below.</li>
   * </ol>
   *
   * <p>This bean is intentionally <b>not</b> the application's primary {@code ObjectMapper}; it is
   * resolved by name through {@code @Qualifier("canonicalJsonMapper")} so it cannot accidentally
   * leak into HTTP responses.
   */
  @Bean
  public ObjectMapper canonicalJsonMapper() {
    SimpleModule canonicalModule = new SimpleModule("canonical-bigdecimal");
    canonicalModule.addSerializer(BigDecimal.class, new CanonicalBigDecimalSerializer());

    ObjectMapper mapper = JsonMapper.builder()
        .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
        .addModule(canonicalModule)
        .build();

    // Per-DTO mix-ins: keep DTOs clean of @JsonIgnore-for-hashing-only annotations.
    // Add new entries here as more idempotent DTOs come online.
    mapper.addMixIn(AccountOperationRequest.class, AccountOperationRequestCanonicalMixin.class);
    mapper.addMixIn(TransferRequest.class, TransferRequestCanonicalMixin.class);

    return mapper;
  }

  private static final class CanonicalBigDecimalSerializer extends JsonSerializer<BigDecimal> {
    @Override
    public void serialize(BigDecimal value, JsonGenerator gen, SerializerProvider serializers)
        throws IOException {
      // stripTrailingZeros() collapses "100", "100.0", "100.00" to the same magnitude, but it can
      // produce engineering-notation strings like "1E+2" or "0E-0". toPlainString() rewrites those
      // as "100" and "0", which is what we want for a stable, human-readable canonical form.
      gen.writeNumber(value.stripTrailingZeros().toPlainString());
    }
  }
}
