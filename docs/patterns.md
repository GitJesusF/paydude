# PayDude — Design Patterns & Decisions

The engineering decisions behind PayDude, each written as an informal ADR
(context → decision → rationale → trade-offs). This is the in-depth companion to the
[README highlights](../README.md#highlights); the [architecture doc](architecture.md) treats
these as its §9 architecture decision records.

---

### 1. Deadlock-free pessimistic locking
Concurrent transfers A→B and B→A are the classic circular-lock deadlock. The transfer service acquires `SELECT FOR UPDATE` locks **in alphabetical order by `account_number`**, so two conflicting transfers serialise cleanly instead of deadlocking.
→ `TransactionServiceImpl.transfer()` · `AccountRepository.findByAccountNumberForUpdate`

### 2. Idempotent money movements (lookup-under-lock)
Every money-moving command (`transfer`, `deposit`, `withdraw`) requires an `Idempotency-Key` header. `reserveKey` looks the `(key_value, user_id)` row up first **under a `PESSIMISTIC_WRITE` lock** and inserts only when it is absent; the lock serializes concurrent duplicates so the reservation can never fork. The operation scope plus request body are fingerprinted (SHA-256 of the canonical JSON), so retries with a mutated body under the same key are detected and rejected. The operation scope is important: a key used for `accounts.deposit` can never replay an `accounts.withdraw` response, even if both payloads contain the same amount. A row past its TTL is **reclaimed in place** as a fresh reservation — after expiry the key is reusable like any unused one.

This replaced an earlier insert-first variant (optimistic INSERT, catch the `DataIntegrityViolationException`, then read the existing row). That pattern reads well but is **unsafe on PostgreSQL**: a UNIQUE violation aborts the transaction, so the recovery `SELECT` in the catch block fails (Hibernate flushes the failed null-id entity → `AssertionFailure`) — idempotent retries returned 500 instead of the cached result. A mocked-repository unit test hid it; `IdempotencyKeyReservationIT` now drives the real Postgres collision. The one UNIQUE violation that survives the lookup-first design — two first-time requests racing on a brand-new key — is reported as in-progress *without* a follow-up query, since that transaction is already aborted.
→ `IdempotencyKeyServiceImpl.reserveKey()`

### 3. Three ObjectMappers, one per responsibility
The idempotency layer cannot share `ObjectMapper` configuration with HTTP serialization without leaking changes from one into the other. `IdempotencyConfig` defines three named beans:

| Bean | Job | Pinned config |
|------|-----|----------------|
| `objectMapper` (`@Primary`) | HTTP request/response | Built via `Jackson2ObjectMapperBuilder` so it inherits `spring.jackson.*` and Spring Boot customizers. |
| `canonicalJsonMapper` | SHA-256 fingerprint of idempotent requests | Alphabetic field ordering, `BigDecimal` trailing-zero stripping, per-DTO Jackson **mix-ins** (`TransferRequestCanonicalMixin` and `AccountOperationRequestCanonicalMixin` exclude `description` from the digest — Stripe / Square convention). |
| `responseCacheMapper` | Serialize/deserialize `idempotency_keys.response_body` | Independent `JsonMapper.builder()` with `JavaTimeModule` + `WRITE_DATES_AS_TIMESTAMPS=false`. Decouples the durable cache format from any future `spring.jackson.*` change, so old and new rows never coexist in incompatible shapes. |

The pipeline is type-safe via the `sealed interface IdempotentRequest`, so the universe of idempotent request bodies is visible at the type level — adding a new one is a `permits` clause change, reviewable at compile time.
→ `IdempotencyConfig` · `TransferRequestCanonicalMixin` · `AccountOperationRequestCanonicalMixin` · `IdempotentRequest`

### 4. Event-driven rollback handling
The idempotency reservation runs in `REQUIRES_NEW`, so the row survives an outer rollback. A `@TransactionalEventListener(phase = AFTER_ROLLBACK)` then flips the key from `PENDING` to `FAILED` in a new transaction — no dangling reservations after a failed money movement. The same eventing pattern is used at `BEFORE_COMMIT` to atomically open a default account when a user registers.
→ `IdempotencyCleanupListener` · `IdempotencyKeyReservedEvent` · `AccountEventListener` · `UserRegisteredEvent`

### 5. Complete `UserDetails` contract
All four Spring Security state checks are implemented and mapped to domain states, each raising the specific exception the framework expects:

| Check | Backed by | Exception on failure | HTTP |
|---|---|---|---|
| `isEnabled()` | `status == ACTIVE` | `DisabledException` | 403 |
| `isAccountNonLocked()` | `status != LOCKED` | `LockedException` | 423 |
| `isAccountNonExpired()` | `accountExpiresAt > now` | `AccountExpiredException` | 401 |
| `isCredentialsNonExpired()` | `passwordChangedAt + N days > now` | `CredentialsExpiredException` | 401 |

Credential rotation is **disabled by default** (per **NIST SP 800-63B §5.1.1.2**, which discourages periodic forced rotation) and opt-in via `application.security.credentials-expiration-days` for environments where legacy compliance requires it. `isAccountNonLocked()` is no longer only admin-driven: the anti-bruteforce lockout (#22) transitions accounts to `LOCKED` automatically after repeated failed logins, and auto-releases them once the cooldown elapses.
→ `SecurityUser`

### 6. Stateless auth without DB hits on the hot path
`JwtAuthenticationFilter` rebuilds `SecurityUser` from JWT claims (`sub = userId`, `userId`, `role`, `status`, `accountExpiresAt`, `credentialsExpireAt`) on every authenticated request. Only login touches the DB, via `CustomUserDetailsService`. Failures from the filter (bad signature, expired token, degraded account state) are forwarded through Spring MVC's `HandlerExceptionResolver` so they reach the per-concern advice classes (see [Exception handling split by concern](#9-exception-handling-split-by-concern-not-by-class)) and produce the same `ErrorResponse` shape as the rest of the API — no two error formats leaking to clients.
Trade-off: admin-driven status changes (`SUSPENDED`, `LOCKED`) take effect on next token issuance. Time-based expirations are evaluated against the current clock and take effect immediately.
→ `JwtAuthenticationFilter` · `JwtService` · `CustomSecurityExceptionHandler`

### 7. OAuth 2.0-style separation between token issuance and profile retrieval
`/v1/auth/login`, `/v1/auth/register` and `/v1/auth/refresh` return OAuth-style token-pair fields (`accessToken`, `tokenType`, `expiresIn`, `refreshToken`, `refreshExpiresIn`) and **no profile fields** — no email, no display name. Profile data lives behind `GET /v1/users/me`, called separately by clients that need it. Two consequences fall out:

- **Login does exactly one DB read for the credential check.** `DaoAuthenticationProvider` already loads the user through `CustomUserDetailsService` to verify the password and exposes the resulting `SecurityUser` as the `Authentication` principal. The service casts that principal, builds the JWT from its claims, and returns the response — without touching the repository a second time. The previous `findByEmail`-after-`authenticate` pattern (an extra query just to fetch `firstName` for the response) is gone. (It is one *read*; login is still `@Transactional(rollbackFor = Exception.class)` because it *writes* the rotating refresh-token row via `issueNewFamily`, and the lockout counters write in their own `REQUIRES_NEW` transactions — see #19 and #22.)
- **JWTs stay free of PII.** The token carries authorization data only (`sub = userId`, `userId`, `role`, `status`, expiry windows). Names and emails are not embedded — they would bloat every request, leak through logs and proxies, and stale-out the moment a user edits their profile. This mirrors how Stripe, Auth0, Google and Okta shape their token responses.

The trade-off is a second round-trip on the client at startup (`/v1/auth/login` → `/v1/users/me`). It buys a smaller token, a token endpoint that can be reused for refresh flows without recomputing profile data, and clean single-responsibility boundaries between authentication artifacts and user-domain queries.
→ `AuthServiceImpl.login` · `AuthResponse` · `UserController`

### 8. URI path versioning
Every controller is mounted under `/v1` via a marker annotation (`@ApiV1`) and a single `WebMvcConfigurer` that prepends the prefix at routing time:

```java
configurer.addPathPrefix("/v1", HandlerTypePredicate.forAnnotation(ApiV1.class));
```

Controllers stay declarative (`@RequestMapping("/auth")`) — versioning is one annotation, not a global find-and-replace. Adding `/v2` later is a new marker plus a second `addPathPrefix` call; the v1 controllers are untouched, and Swagger UI picks up both versions automatically because springdoc reads the resolved handler mappings rather than the raw `@RequestMapping` strings.

URI path versioning was chosen over header-based negotiation (`Accept: application/vnd.paydude.v1+json`) deliberately. It's the convention adopted by Stripe, Plaid, GitHub and AWS — visible in logs, trivial to cache at the proxy layer, obvious in Postman and curl. Header versioning is more "RESTful" in the strict Fielding sense, but it makes the live API harder to inspect and forces clients to remember a version header on every call. For a financial API where operators routinely tail logs and replay requests during incidents, having the version in the URL is worth the small loss of theoretical purity.
→ `ApiV1` · `WebConfig`

### 9. Exception handling split by concern, not by class
Spring's idiomatic catch-all is one big `@RestControllerAdvice` with every `@ExceptionHandler` jammed in. That's fine at small scale but turns into a hot file with diffuse ownership and constant merge conflicts as the app grows. PayDude splits the advice into six classes by concern, with explicit `@Order` precedence:

| Order | Advice | Concern | HTTP statuses |
|-------|--------|---------|---------------|
| 10 | `ValidationExceptionHandler` | Request shape, format, HTTP protocol | 400, 405, 415 |
| 20 | `SecurityExceptionHandler` | Authentication and authorization | 401, 403, 423 |
| 30 | `BusinessExceptionHandler` | Domain rule violations | 404, 409 |
| 40 | `PersistenceExceptionHandler` | JPA / DB constraints | 409 |
| 50 | `RateLimitExceptionHandler` | Throttling | 429 |
| `LOWEST_PRECEDENCE` | `RootExceptionHandler` | Catch-all | 500 |

`@Order(LOWEST_PRECEDENCE)` on the catch-all is load-bearing, not cosmetic. Spring iterates advice beans in `@Order` and resolves the first match — so without it, a `RootExceptionHandler` evaluated early would catch every `Exception` subclass and shadow the specific advices, turning what should be a 400 validation error into a 500 internal error. Putting it last guarantees the specific advices always run first.

Logging follows a strict, observable rule: **all 4xx handlers log at `WARN` with one line and no stack trace; only the catch-all 5xx logs at `ERROR` with the full stack trace.** This keeps ops dashboards focused — `count(level=ERROR)` only spikes during real incidents, never when a client sends a malformed body or hits the wrong verb. The 405 handler additionally emits the `Allow` header per RFC 9110 §15.5.6 so automated clients can recover by switching verbs without parsing the body, and 415 narrows the message to "use application/json" so the recoverability is obvious. A small `ErrorResponses` utility centralises the response construction so every advice produces the same `ErrorResponse` shape.
→ `ValidationExceptionHandler` · `SecurityExceptionHandler` · `BusinessExceptionHandler` · `PersistenceExceptionHandler` · `RateLimitExceptionHandler` · `RootExceptionHandler` · `ErrorResponses`

### 10. Framework-agnostic pagination envelope
Returning Spring Data's `Page<T>` directly from a controller serializes the internal `PageImpl` shape — fields like `pageable`, `sort`, `unpaged`, `empty`, plus a duplicated `sort` block — into the wire payload. Spring Boot 3.2+ explicitly warns against this because the JSON structure is not part of any stable contract and can change across Spring Data versions. PayDude maps every paginated endpoint to a `PagedResponse<T>` record owned by this codebase:

```json
{
  "content": [ ... ],
  "page": 0,
  "size": 20,
  "totalElements": 137,
  "totalPages": 7,
  "hasNext": true
}
```

Six fields, no leaks. Services still return `Page<T>` internally because it's convenient with `JpaRepository`; only the controller boundary swaps to `PagedResponse.from(page)`. This is the shape consumed by paginated clients of Stripe, GitHub and AWS — minimal, versionable under `/v1`, and OpenAPI-generator-friendly. `TransactionControllerTest` pins the contract with both positive assertions (the six fields exist) and negative assertions (`$.pageable`, `$.sort`, `$.empty` must NOT exist), so any regression that reintroduces the `PageImpl` shape fails loudly.
→ `PagedResponse` · `TransactionController` · `AccountController`

### 11. Type-safe configuration with `@ConfigurationProperties`
Spring's `@Value` injection is convenient but quietly scales into a maintenance hazard: the same property ends up read in two unrelated classes, one drifts, and the bug only surfaces in production when a token says one thing and the service enforces another. PayDude binds every `application.security.*` property to a single immutable `SecurityProperties` record:

```java
@ConfigurationProperties(prefix = "application.security")
@Validated
public record SecurityProperties(
    @NotNull @Valid Jwt jwt,
    @PositiveOrZero int credentialsExpirationDays
) {
  public record Jwt(@NotBlank String secretKey, @Positive long expiration) {}
}
```

Three concrete wins over the `@Value` baseline this replaced:
- **Single source of truth.** `credentials-expiration-days` used to live in two `@Value` fields (`CustomUserDetailsService` and `AuthServiceImpl`). If one had drifted, the rotation window applied at login would silently differ from the one embedded in the JWT.
- **Fail-fast at boot.** `@Validated` + the bean-validation annotations make a missing/malformed property fail at application startup, not on the first login attempt with an `NPE` or a malformed JWT.
- **Observable config.** Spring Boot's `/actuator/configprops` exposes every bound value and its origin (which `application-*.properties` file or environment variable supplied it) — an operator verifies live config without restarting or grepping the codebase.

Test impact: `JwtServiceTest`, `CustomUserDetailsServiceTest` and `AuthServiceTest` dropped `ReflectionTestUtils.setField` (which only worked because the fields were package-private and quietly broke on rename) in favor of constructing the record literal — a compile-time-verified contract.
→ `SecurityProperties` · `Application` (`@ConfigurationPropertiesScan`)

### 12. W3C Trace Context propagated through MDC
Adding `micrometer-tracing-bridge-otel` hands Spring Boot the W3C **Trace Context** standard. Boot reads the inbound `traceparent` header — if a gateway or upstream service already started a trace — or mints a fresh trace id, and places `traceId` / `spanId` in SLF4J's `MDC`. The dev/test console pattern reads `%X{traceId:-}`; in prod the `LogstashEncoder` flattens both into the JSON log line. No trace backend is wired (no Tempo / Jaeger exporter) — the bridge is here for standards-based propagation and log correlation, not span shipping, so `management.tracing.sampling.probability=1.0` costs nothing.

```
2026-05-10 14:23:01 [http-nio-8090-exec-3] [b6c89be8e55d57841205db0cc26ad68a] WARN  c.j.p.exception.handler.BusinessExceptionHandler - Idempotency key already used with different request parameters
```

Two non-obvious details:
- **No custom filter to maintain.** The trace context is opened by Boot's `ServerHttpObservationFilter` (`Ordered.HIGHEST_PRECEDENCE + 1`) — earlier in the servlet chain than Spring Security, so authentication failures inside `JwtAuthenticationFilter` and every per-concern advice already find a populated MDC. Cleanup on span-scope close is the framework's job, not a hand-written `finally` block — this replaces a bespoke `CorrelationIdFilter` that did all of it by hand.
- **`traceparent` over a bespoke header.** A trace id minted here propagates automatically to any downstream service that speaks the standard, and the day a trace backend (Tempo, Jaeger) is added it integrates with zero code change. The trade-off versus the old `X-Correlation-Id` filter: a client can no longer read its id back from a response header — to correlate, it sends its own `traceparent`.

→ `pom.xml` (`micrometer-tracing-bridge-otel`) · `logback-spring.xml` · `application.properties` (`management.tracing.sampling.probability`)

### 13. Custom business metrics behind a single facade
Every observable signal that an operator might pin a Grafana panel on — completed transfers, failed transfers broken down by domain reason, transfer wall-clock duration, idempotency replays and conflicts, login success/failure split, registrations — is emitted through a single `BusinessMetrics` component. Services and controllers never touch the `MeterRegistry` directly: they call `metrics.recordTransferFailed(TransferFailureReason.INSUFFICIENT_FUNDS)`. The tag value is an enum, not a string, so a typo in one call-site can't fork the time series into `Insufficient funds` and `insufficient` — exactly the kind of cardinality explosion that quietly degrades a TSDB.

```
paydude.transfer.completed                       (Counter)
paydude.transfer.failed{reason=INSUFFICIENT_FUNDS, OWNERSHIP_VIOLATION, ...}
paydude.transfer.duration                        (Timer — feeds p95/p99 SLO panels)
paydude.idempotency.replay                       (work the layer saved)
paydude.idempotency.conflict{reason=HASH_MISMATCH, ...}
paydude.auth.login{outcome=success|failure}      (credential-stuffing signal)
paydude.auth.register
```

Three non-obvious details:
- **Pre-registration with descriptions.** Counters without tags are built with `Counter.builder(name).description(...).register(registry)` in the constructor so they appear in `/actuator/metrics` with a human-readable description before the first increment — the dashboard renders a flat line at zero instead of `no data`, and an operator skimming the catalog can identify what each meter means without reading source. The Prometheus scrape format ships out of the box via `micrometer-registry-prometheus` (see pattern #16) — every meter declared here is published at `/actuator/prometheus` in OpenMetrics text without further wiring.
- **Tag values from enums, never strings.** `TransferFailureReason` and `IdempotencyConflictReason` live inside the facade as `enum`s; the call-site cannot accidentally emit `"insufficient"` or `"Insufficient funds"`. The Prometheus exporter sees one series per enum value, period.
- **Timer.Sample with `try/finally` at the call-site.** `executeTransfer` opens the sample, runs the transfer body, and stops the sample in `finally` so the latency distribution stays accurate on the failure path. Forgetting the `finally` would let the failure-path latency disappear from p99 and the dashboard would lie during incidents.

→ `BusinessMetrics` · `BusinessMetricsTest`

### 14. Profile-aware logging: human-readable in dev, JSON in prod
The same trace id from pattern #12 is useless if a log collector can't parse it. `logback-spring.xml` declares two appenders gated by `<springProfile>`: the `dev`/`test` profile keeps the human-readable pattern (timestamp, thread, trace id, level, logger, message) for terminal eyeballing, while `prod` swaps the encoder to `LogstashEncoder` — every log event becomes a single-line JSON document on stdout, ready for Loki / Filebeat / Fluent Bit / CloudWatch without regex parsing at the collector.

```json
{"timestamp":"2026-05-10T14:23:01.412Z","level":"WARN","logger":"c.j.p.exception.handler.BusinessExceptionHandler",
 "thread":"http-nio-8090-exec-3","message":"Idempotency key already used with different request parameters",
 "traceId":"b6c89be8e55d57841205db0cc26ad68a","spanId":"1205db0cc26ad68a","application":"paydude","environment":"prod"}
```

Three details worth calling out:
- **MDC flattens automatically.** Whatever lands in MDC becomes a top-level JSON field — `traceId` and `spanId` from the tracing bridge, plus anything added later (`MDC.put("userId", id)`) — no encoder reconfig needed.
- **`customFields` injects deployment metadata once.** `application=paydude` and `environment=prod` ride on every log line, so a single Loki query can scope to this service across a multi-service cluster.
- **`logback-spring.xml`, not `logback.xml`.** The `-spring` suffix is what unlocks `<springProfile>` — plain Logback has no notion of Spring profiles. A property in `application.properties` can change the pattern but not the encoder, so swapping text ↔ JSON requires the XML route.

→ `logback-spring.xml` · `pom.xml` (`logstash-logback-encoder`)

### 15. Standardised error responses with RFC 9457 Problem Details
Every 4xx and 5xx returned by the API now ships as a [Problem Details](https://www.rfc-editor.org/rfc/rfc9457.html) document (the standard that obsoletes RFC 7807), served as `application/problem+json`. The body has five standard fields — `type`, `title`, `status`, `detail`, `instance` — plus two extension properties (`timestamp`, and `errors` on validation failures). No bespoke `ErrorResponse` DTO; the body is `org.springframework.http.ProblemDetail`, which Spring 6 / Boot 3 ship as a first-class value type and auto-wire the content type for.

```json
{
  "type": "/problems/business-conflict",
  "title": "Business Conflict",
  "status": 409,
  "detail": "Source account does not belong to the authenticated user",
  "instance": "/v1/transactions/transfer",
  "timestamp": "2026-05-10T14:23:01.412Z"
}
```

Validation errors keep the same envelope but carry the field map as an extension property, so clients can render messages inline without parsing `detail`:

```json
{
  "type": "/problems/validation-error",
  "title": "Validation Error",
  "status": 400,
  "detail": "Invalid input data",
  "instance": "/v1/auth/register",
  "timestamp": "2026-05-10T14:23:01.412Z",
  "errors": { "email": "must be a well-formed email address", "firstName": "must not be blank" }
}
```

Three design decisions worth flagging:
- **`type` is a relative URI by category, not by occurrence.** RFC 9457 §3.1.1 explicitly allows relative URI references, which sidesteps having to hardcode a hostname into responses (the host typically differs between the internal pod and the public LB). `/problems/<slug>` groups errors by domain category — `not-found`, `business-conflict`, `validation-error` — so a client can branch on it without coupling to free-text titles. A future docs site can resolve the URI against the base URL of the API.
- **Two extension properties, set via `ProblemDetail.setProperty(...)`.** RFC 9457 §3.2 endorses extension fields. `timestamp` rides on every body (post-mortem log correlation); `errors` rides only on 400s where it adds value. The standard `detail` field stays a single human-readable sentence — extension properties are how you carry machine-parseable data.
- **One helper, six advice classes.** `ErrorResponses.of(...)` is the single factory; each per-concern `@RestControllerAdvice` calls it. The two handlers that need a response header (`Retry-After` for 429, `Allow` for 405) call the lower-level `buildProblem(...)` and wrap the body manually — the only divergence from the shared path, and it's localised.

→ `ProblemDetail` · `ErrorResponses` · per-concern advices under `exception/handler/`

### 16. Production-ready Actuator surface, split by trust tier
The `BusinessMetrics` work in pattern #13 only pays off if a Prometheus scraper can reach it and an operator can introspect the running JVM safely. Actuator is enabled with two trust tiers, both wired through `SecurityConfig` using `EndpointRequest` (the official Boot API) rather than hardcoded paths — so a future Boot rename or a `management.endpoints.web.base-path` override cannot silently widen or narrow the exposure:

| Tier | Endpoint | Auth | Consumer |
|------|----------|------|----------|
| Public | `/actuator/health` (+ `/liveness`, `/readiness`) | `permitAll` | Kubernetes probes, Docker `HEALTHCHECK`, load balancer |
| Public | `/actuator/info` | `permitAll` | Deploy verification (build version, git commit, build time) |
| Admin | `/actuator/prometheus`, `/metrics`, `/loggers`, `/configprops`, `/env` | `hasRole("ADMIN")` | Operator runtime introspection + metrics scrape |

Actuator lives in its **own `SecurityFilterChain`** (`@Order(1)`, `securityMatcher(EndpointRequest.toAnyEndpoint())`), separate from the JWT API chain (`@Order(2)`). Inside it, `health`/`info` are `permitAll` and `.anyRequest().hasRole("ADMIN")` covers everything else — no `.excluding(...)`, so **any new endpoint enabled in the future inherits the admin policy by default** — fail closed, not open. Adding `heapdump` or `threaddump` in dev does not require remembering to lock it down separately. `/actuator/prometheus` is admin-gated on purpose: it exposes the full meter catalog, so the scrape endpoint is operator-grade introspection, not a public surface.

The admin tier authenticates with **HTTP Basic (RFC 7617)**, backed by a dedicated *technical* account — `application.security.actuator.{username,password}`, loaded into an `InMemoryUserDetailsManager` scoped to this chain. It is deliberately decoupled from the application `users` table: a Prometheus scraper or on-call operator is a machine/role, not a banking customer, so it carries no domain user row, BCrypt login hash, or refresh-token family. Confining Basic to this chain keeps the API surface JWT-only — a `Basic` header is never a valid credential for `/v1/**`. The password is baked for local convenience in dev (matched in `observability/prometheus.yml` so the Grafana stack scrapes with no setup) and made mandatory in prod via `ACTUATOR_PASSWORD` (the prod compose overlay fails fast if it is unset).

Five non-obvious details:
- **`management.endpoint.health.show-details=when-authorized` in prod.** Anonymous probes get `{"status":"UP"}`; only authenticated admins see the DB pool, disk and Flyway component breakdown. Leaking those details to anonymous scanners is a recon vector. Dev keeps `show-details=always` because nothing sensitive ships and the audience is the laptop.
- **Liveness vs readiness, both enabled.** `management.endpoint.health.probes.enabled=true` + the `livenessstate` / `readinessstate` health indicators expose `/actuator/health/liveness` and `/actuator/health/readiness`. Combined with `server.shutdown=graceful` and a 30s `timeout-per-shutdown-phase`, readiness flips to OUT_OF_SERVICE on SIGTERM so the platform stops sending traffic before in-flight requests are interrupted — the rolling-deploy story expected from a service that handles money.
- **`build-info` goal on the Spring Boot Maven plugin.** Writes `META-INF/build-info.properties` at package time, so `/actuator/info` returns app name, group, artifact, version and build timestamp. Without this, `/actuator/info` answers `{}` and a deployed pod can't be matched back to a commit without grepping the manifest.
- **`configprops` and `env` sanitization is explicit.** `management.endpoint.configprops.show-values=never` and `management.endpoint.env.show-values=never` are set in prod even though Boot 3 already redacts `password`/`secret`/`token`/`key` by default. Pinning the policy means a future Boot upgrade that changes the default cannot silently widen the exposure.
- **Docker container healthcheck wired to readiness.** `docker-compose.yml` runs `wget -qO- http://localhost:8090/actuator/health/readiness` with a 60s `start_period` so cold-start (Flyway + Hibernate metamodel scan) is not flagged as unhealthy. The same pattern lifts directly into a Kubernetes `readinessProbe` / `livenessProbe` block with no code change — the endpoints already exist.

→ `SecurityConfig` · `application.properties` (cross-profile probes) · `application-prod.properties` (narrow exposure) · `application-dev.properties` (full surface) · `pom.xml` (`build-info` goal, `micrometer-registry-prometheus`)

### 17. Self-contained local observability stack
Exposing `/actuator/prometheus` is half the story — without a scraper, a TSDB and a dashboarding layer, the metrics are just text on an HTTP endpoint. PayDude ships an opt-in Docker Compose overlay that boots the full **Grafana Labs stack** (Prometheus + Loki + Promtail + Grafana) against the running app, with datasources and a starter dashboard provisioned automatically.

```bash
docker-compose -f docker-compose.yml -f docker-compose.observability.yml up
```

Then open `http://localhost:3000` — Grafana opens without a login (anonymous Admin) and the **"PayDude — Golden Signals"** dashboard is already in the `PayDude` folder. No clickops, no manual datasource setup.

The four containers each have one job, mirroring how a real cluster is structured:

| Service | Role | Scrapes / consumes |
|---------|------|---------------------|
| `prometheus` | Pulls `/actuator/prometheus` every 15s and stores the time-series. | `app:8090/actuator/prometheus` |
| `loki` | Append-only log database, queryable via LogQL. | (nothing directly) |
| `promtail` | Discovers every container via `docker_sd` and reads stdout/stderr through the Docker API, parses the JSON of `paydude-app`, ships to Loki. | Docker socket (`/var/run/docker.sock`) |
| `grafana` | Visualisation; connects to both stores. | Prometheus + Loki |

The dashboard is intentionally small — golden-signal panels covering the **RED method** (Rate, Errors, Duration), the account-security counters, and a logs pane:

- **Transfer rate (completed vs failed)** — stacked by `reason` tag, so a spike of `INSUFFICIENT_FUNDS` is immediately distinguishable from `CURRENCY_MISMATCH`.
- **Transfer latency p50 / p95 / p99** — built from `paydude_transfer_duration_seconds_bucket` via `histogram_quantile`. SLO panels pin on p95.
- **Login outcome rate** — `success` vs `failure`, the credential-stuffing signal.
- **Account lockouts & MFA outcomes** — lockouts as `increase(...[5m])` (one account locking is a forgotten password; many distinct accounts locking together is credential stuffing) next to the step-up verification `success`/`failure` rate — wrong MFA codes feed the same lockout as wrong passwords, so the two panels read together.
- **Idempotency replays vs conflicts** — replays measure work the layer saved; conflicts measure broken clients or replay attacks.
- **Built-in JVM/HTTP/DB stats** (collapsed row) — heap, request rate, HikariCP active connections, uptime — straight from the meters Spring Boot Actuator pre-registers.
- **Recent WARN/ERROR logs** — Loki query `{container="paydude-app"} | json | level=~"WARN|ERROR"`. Click a row to drill into the `traceId` and follow the trail of a single failed request.

Three non-obvious decisions worth flagging:

- **Compose overlay, not a separate file.** Run `docker-compose up` on its own and you get the production-like stack (no observability noise). Add `-f docker-compose.observability.yml` only when you want to watch metrics live. The split keeps the everyday `up` command lean.
- **Promtail's JSON pipeline.** When the app runs in the `prod` profile (the default for `docker-compose.yml`), every log line is a `LogstashEncoder`-formatted JSON document. Promtail's `pipeline_stages` parse that JSON and elevate `level` to a Loki label and `traceId`/`spanId`/`logger` to structured metadata — so the LogQL filter `| level="ERROR"` Just Works without scanning the message body.
- **Grafana auto-provisioning.** `provisioning/datasources/datasources.yml` and `provisioning/dashboards/dashboards.yml` are mounted read-only at boot. The dashboard JSON in `dashboards/` is reloaded every 30s, so iterating on a panel is a `git pull` + container reload, not a manual import via the UI.

→ `docker-compose.observability.yml` · `observability/prometheus.yml` · `observability/loki-config.yml` · `observability/promtail-config.yml` · `observability/grafana/`

### 18. Layered rate limiting — infrastructure tier in a filter, business tier in the controller

Per-IP throttles (cheap, coarse, oblivious to payload) and per-account throttles (need parsed body, need to see auth outcome) belong in different places. PayDude splits them along that exact seam:

| Tier | Component | Key | Why it lives there |
|------|-----------|-----|--------------------|
| Infra | `IpRateLimitFilter` (`security/ratelimit/`) | peer IP | Servlet filter at `Ordered.HIGHEST_PRECEDENCE + 10`. Runs before Spring Security and before dispatcher resolution, so a throttled auth request never pays BCrypt (~100 ms/call), body validation, or DB lookup. |
| Business (auth) | `AuthRateLimiter` called from `AuthController.login` | canonical email (trimmed + lowercased) | Needs the parsed `LoginRequest` and the post-auth success signal to refund a token on a successful login — both unavailable in a pre-controller filter. |
| Business (writes) | `WriteRateLimiter` called from `AccountController` / `TransactionController` | authenticated user id | Deposit, withdraw and transfer are bearer-authenticated. The abuse that grows DB state and holds account row-locks is one principal replaying money-moving writes, so rotating IPs must not reset the budget and unrelated users behind shared NAT must not collide. |
| Business (re-auth) | `ReauthRateLimiter` called from `UserController` / `MfaController` | authenticated user id | The account-security management gates — change-password, MFA setup/confirm/disable — sit behind a bearer token but outside the IP and email auth throttles. Without a bound here a stolen token could brute-force the account password (setup/disable/change-password) or the 6-digit confirm code (whose prize is the recovery-code batch) unbounded. |

**Filter chain order**, pinned explicitly: Boot's `ServerHttpObservationFilter` (`HIGHEST_PRECEDENCE + 1`, opens the W3C trace context) → `IpRateLimitFilter` (`HIGHEST_PRECEDENCE + 10`) → Spring Security's `FilterChainProxy` (`-100`). The 429 log line therefore carries the same `traceId` as the rest of the request's trail.

**Bucket storage** uses `Caffeine` caches with `expireAfterAccess` matched to the bucket's refill period and `maximumSize = 100_000` per cache. A plain `ConcurrentHashMap` would retain one entry per unique IP and email forever — an attacker spraying random addresses can weaponize that as an unbounded memory leak. Once a key goes silent for one full period, the bucket has already refilled to capacity, so evicting and recreating is indistinguishable from retaining. Scaling horizontally? Swap the cache for `bucket4j-redis`' `ProxyManager`; the `AuthRateLimiter` API doesn't change.

**Client-IP trust model** is delegated to the framework, never reimplemented in app code. In `prod`, `server.forward-headers-strategy=native` activates Tomcat's `RemoteIpValve`, which unwraps `X-Forwarded-For` **only** when the immediate TCP peer matches `server.tomcat.remoteip.internal-proxies` (RFC 1918 + loopback by default). The filter then reads `request.getRemoteAddr()` and trusts it. Reading `X-Forwarded-For` directly from application code — a common mistake — would let any caller forge their IP by sending the header.

**Method-aware**: only `POST` consumes a token. A `GET` or `OPTIONS` to `/v1/auth/login` passes through. The reason is concrete: counting wrong-method requests would let an attacker drain the bucket of a shared NAT egress IP just by spamming a method that doesn't exist, locking out legitimate users behind that NAT.

**Authenticated writes are deliberately principal-keyed, not IP-keyed in-app.** The money-moving endpoints already sit behind Bearer authentication; once the principal is known, the stable abuse key is `SecurityUser.id()`. A per-IP application bucket on these paths would be weak against IP rotation and unfair to legitimate users sharing one corporate or mobile NAT. Coarse volumetric IP controls still belong at the edge (reverse proxy, WAF, cloud load balancer), where they can reject floods before the JVM, but the application-level control that protects `idempotency_keys`, `transactions`, `account_audits` and pessimistic account locks is the per-user write bucket.

**The password re-auth gates get the same principal-keyed treatment — as a throttle, not a lockout.** `PATCH /v1/users/me/password` and `POST /v1/users/me/mfa/{setup,disable}` re-verify the account password even though the caller already holds a valid access token — precisely so a *stolen* token cannot rotate the password or enroll the attacker's own authenticator (account takeover). But those endpoints sit behind authentication, so neither the per-IP filter nor the per-email login bucket covers them: left unbounded, a token holder who does not know the password could brute-force it at BCrypt speed through these side doors, defeating the whole point of the re-authentication step. `ReauthRateLimiter` closes that gap with a per-user bucket (default 5 / 15 min, mirroring the login-by-email posture — a password re-auth is as sensitive as a login). It is deliberately a **throttle (429), not the account lockout (#22)**: feeding the persistent lockout from a token-authenticated endpoint would let an attacker who holds a token lock the legitimate owner out of *login* — exactly when the owner most needs to log in to revoke the session and change the password. A throttle bounds the guess rate without taking the owner's recovery path away. `/mfa/confirm` shares the bucket for a different reason: it verifies a 6-digit TOTP code, not the password — but that makes it the one *online-guessable* surface among the gates (~3 valid codes per attempt inside the ±1-step window), its wrong-code 409s feed neither the lockout nor any other bucket, and a successful guess against someone else's pending enrollment returns the recovery-code batch. All three operations are rare, human-paced account-security actions, so one shared per-user budget fits them all.

**Error shape stays canonical**. The filter forwards `RateLimitExceededException` through `HandlerExceptionResolver` (same pattern as `JwtAuthenticationFilter`), so it lands in `RateLimitExceptionHandler` and produces the project-wide `application/problem+json` body with a `Retry-After` header. Writing to the response directly from a filter would leak a second error format to clients.

**Proactive quota signalling — IETF `RateLimit` headers.** `Retry-After` only shows up *after* the client is already blocked. The IETF draft `draft-ietf-httpapi-ratelimit-headers` fixes that with two HTTP Structured Fields advertised on every response: `RateLimit-Policy: "login";q=20;w=60` (the static quota `q` per window `w`) and `RateLimit: "login";r=19;t=42` (live `r` remaining, resets in `t` seconds). `IpRateLimitFilter` emits both for the public token endpoints (`/login`, `/register`, `/refresh`) on the 2xx path as well as the 429 — a well-behaved SDK reads `r` and slows down before it trips the limit. The values come from a `RateLimitSnapshot` the bucket returns (`AuthRateLimiter` now consumes via bucket4j's `tryConsumeAndReturnRemaining`, mapping `getNanosToWaitForReset()` to `t`); `RateLimitHeaders` does the structured-field formatting. The snapshot deliberately carries the quota/window too, so the filter needs no `SecurityProperties` dependency — it stays light enough to be component-scanned into `@WebMvcTest` slices without dragging configuration beans into them. This supersedes the de-facto `X-RateLimit-*` triple; the authenticated email/user tiers keep `Retry-After`-only 429s, a mechanical extension away from the same treatment.

→ `IpRateLimitFilter` · `AuthRateLimiter` · `WriteRateLimiter` · `ReauthRateLimiter` · `RateLimitSnapshot` · `RateLimitHeaders` · `IpRateLimitFilterTest` · `AuthRateLimiterTest` · `RateLimitHeadersTest` · `WriteRateLimiterTest` · `ReauthRateLimiterTest` · `AccountControllerTest` · `TransactionControllerTest` · `UserControllerTest` · `MfaControllerTest` · `application-prod.properties` (`server.forward-headers-strategy`)

### 19. Refresh tokens with rotation, reuse detection, and family-based revocation

A long-lived access token is a security liability — every minute it lives is a minute an attacker has if they steal it. The industry answer is a **hybrid** flow: a short-lived access token (15 min here) for the hot path, and a long-lived **refresh token** (7 days) that the client trades in at `/v1/auth/refresh` for a new access token. PayDude implements the design completely, not a simplified version, because the trade-offs are exactly the kind of thing a senior backend engineer is expected to reason about.

**Stateful and opaque, not a JWT.** The refresh token is 32 bytes of `SecureRandom` entropy, base64url-encoded for transport, and persisted only as its SHA-256 digest. The raw value never touches disk; a database compromise yields nothing usable. The opposite choice — a signed JWT refresh token — would defeat the entire reason for adding the layer, since you can't revoke a JWT. The hot path stays 100% stateless (access-token validation is in-memory only); the cold path (`/refresh`, hit roughly once per access-token lifetime) is the only place that touches the new table.

**Single-use rotation with reuse detection.** Every successful `/refresh` revokes the presented token and emits a fresh one in the same **family** (a UUID shared across the rotation chain). If a client ever presents a token that has already been revoked — whether because it was rotated, logged out, or admin-revoked — the service assumes compromise and revokes the entire family in one statement. The legitimate client is forced to re-login; the attacker, who has presumably stolen the token, finds every future request fails. This is the OAuth 2.1 mandate (RFC 9700, current draft) and the pattern Auth0, Okta, and Stripe ship. The blast radius of a stolen refresh token shrinks from "until natural expiry" to "until the legitimate user next refreshes" — usually minutes.

**Family-based revocation as a primitive.** `logout` revokes the family in a single bulk UPDATE; `PATCH /v1/users/me/password` revokes every family belonging to the user via `revokeAllForUser` after verifying the current password (per OWASP ASVS v4 §2.4.5); a future force-logout admin action falls out of the same primitive. One method, three consumers — no per-feature re-architecture.

**Concurrency-safe rotation.** Two requests racing the same raw token (an attacker against the legitimate client, or just a buggy double-firing UI) acquire a `PESSIMISTIC_WRITE` row lock on the lookup. The first transaction rotates; the second waits, finds `revoked_at` set, and trips reuse detection. Without the lock the chain would fork — two valid tokens for the same family — and the whole security model would collapse.

**Audit trail.** Each row records the issuing IP and User-Agent (captured via `HttpServletRequest.getRemoteAddr()` and the header, both safe in prod because Tomcat's `RemoteIpValve` is active — see item 18). `replaced_by_token_id` walks the chain forward, so investigating a suspected reuse incident is a single SQL query, not a heuristic search through logs.

**Rate-limited like the rest of the auth surface.** `POST /v1/auth/refresh` consumes the `refreshByIp` bucket in the same `IpRateLimitFilter` from item 18 (60 requests / hour / IP by default — plenty for legitimate clients refreshing 4×/hour per active session, hostile to enumeration). Logout is *not* throttled: a user that wants to log out must always succeed.

→ `RefreshToken` · `RefreshTokenService` · `RefreshTokenServiceImpl` · `RefreshTokenRepository` · `AuthServiceImpl.refresh()` · `AuthController` · `V0_002__create_refresh_tokens.sql` · `RefreshTokenServiceTest`

### 20. Breached-password screening with k-anonymity

A password policy that only checks length is theatre — the passwords that actually get accounts compromised are the ones already sitting in every credential-stuffing wordlist. PayDude screens every chosen password, at registration and at rotation, against the [HaveIBeenPwned](https://haveibeenpwned.com/Passwords) breach corpus, implementing the part of **NIST SP 800-63B §5.1.1.2** that says verifiers SHALL reject secrets known to be compromised.

**k-anonymity, never the raw password.** The check sends the password nowhere. Spring Security's `HaveIBeenPwnedRestApiPasswordChecker` SHA-1-hashes it locally and sends only the first **five hex characters** of the digest to the range API; the API returns every breached suffix under that prefix, and the match happens in-process. A network observer — or HaveIBeenPwned itself — learns nothing usable.

**Fail-open, on purpose.** `BreachedPasswordGuard` wraps the checker with a deliberate degradation policy: if the HaveIBeenPwned API is unreachable, the check is skipped (logged at `WARN`) rather than blocking the user. A third-party outage must not take down signup or password changes. The alternative — fail-closed — hands an attacker a denial-of-service vector against your own registration endpoint by knocking over someone else's API.

**Domain exception, not a security exception.** A compromised password surfaces as a `BusinessException` → HTTP 409, travelling the same per-concern advice path and `ProblemDetail` shape as every other domain-rule rejection (see pattern #15). Spring Security's own `CompromisedPasswordException` was deliberately *not* used — it extends `AuthenticationException` and would map to 401, the wrong semantics for "the password you chose is unacceptable".

**No breach oracle.** In `changePassword` the screening runs *after* the current-password check, never before. Reversing the order would let anyone holding a stolen access token probe whether arbitrary passwords are breached — turning the endpoint into a free HaveIBeenPwned proxy bound to the victim's session.

**Profile-gated.** The live checker is wired only when `application.security.password.breach-check-enabled` is true (the cross-profile default). The `test` profile sets it false and `SecurityConfig` swaps in a no-op decision, so integration tests never reach for the public network — flaky, externally-dependent tests are not worth paying for coverage of a fail-open path that unit tests already pin directly.

→ `BreachedPasswordGuard` · `BreachedPasswordGuardTest` · `SecurityConfig.compromisedPasswordChecker` · `SecurityProperties.Password` · `AuthServiceImpl.register` · `UserServiceImpl.changePassword`

### 21. Sealed outcome types for branched domain operations

`IdempotencyKeyService.reserveKey` has exactly two non-exceptional outcomes: a fresh slot was inserted (caller executes the operation) or an existing COMPLETED row was matched (caller returns the cached body). Returning a raw `IdempotencyKey` and switching on its persistence-level `status` enum forced consumers to carry a dead `case FAILED -> throw new IllegalStateException(...)` arm — FAILED is rejected with `BusinessException` *inside* `reserveKey` and can never reach the call-site, but the type system did not know that, so every consumer paid the cost of pretending it could. PayDude models the result as a `sealed interface ReservationOutcome` with two records, and the dead branch disappears at compile time.

```java
sealed interface ReservationOutcome {
  record Fresh(IdempotencyKey key) implements ReservationOutcome { /* requireNonNull */ }
  record Replay(Long keyId, String cachedResponseBody) implements ReservationOutcome { /* requireNonNull on both */ }
}
```

Four things this buys beyond cosmetics:

- **Exhaustive call-sites with no escape hatch.** `TransactionServiceImpl.transfer` and `AccountServiceImpl.executeIdempotentAccountOperation` now switch over `{Fresh, Replay}` — exactly the variants that exist on the happy path. Adding a third outcome later forces every consumer to decide what it means; today there is no longer a "should never happen" line to maintain or audit.
- **The contract is documented at the type level.** Reading the signature of `reserveKey` tells a reviewer that two outcomes exist and what each carries. Previously they had to read the implementation to learn that COMPLETED/PENDING/FAILED status values had wildly different consumer semantics (return cached / wait / reject).
- **`Replay` cannot carry a null body.** The record's compact constructor calls `Objects.requireNonNull(cachedResponseBody, ...)`, so the variant is *intrinsically* "ready to use". The defensive null check that previously lived (duplicated) in `TransactionServiceImpl.replayCachedResponse` and `AccountServiceImpl.replayCachedAccountResponse` moved upstream into `reserveKey`, where the missing body is converted into a `BusinessException` at the only layer that has the information to detect it.
- **`Fresh` exposes the entity; `Replay` hides it.** The caller of `Fresh` needs the `IdempotencyKey` to publish `IdempotencyKeyReservedEvent` and eventually call `complete(key, body)`. The caller of `Replay` only needs the cached body and the id (for log correlation on JSON corruption) — exposing the full mutable entity would let it `.getStatus()` and re-introduce the persistence-level coupling the refactor removed. Each variant carries exactly what its consumer earns.

Trade-off considered and rejected: a full `Result<T, E>` / `Either` pattern across services. It conflicts with Spring's exception-driven `@Transactional` rollback (a returned `Result.failure(...)` does not trigger rollback — the transfer would commit a half-state), with the per-concern advice handlers (see #9), and with the existing Mockito/MockMvc test patterns. Sealed outcome types are the targeted application of the same idea where it earns its complexity — where there is a genuine branching of *successful* outcomes — without forcing the rest of the codebase to fight the framework.

→ `IdempotencyKeyService.ReservationOutcome` · `IdempotencyKeyServiceImpl.reserveKey` · `TransactionServiceImpl.transfer` · `AccountServiceImpl.executeIdempotentAccountOperation` · `IdempotencyKeyServiceTest`

### 22. Account lockout that completes the LOCKED state

`UserStatus.LOCKED` existed from day one — `SecurityUser.isAccountNonLocked()` mapped it to `LockedException` (HTTP 423), the per-concern advice rendered the `account-locked` `ProblemDetail`, and a comment on the check even named the intended trigger ("too many consecutive failed login attempts"). But nothing ever *set* the state: there was no failed-attempt counter and no code path that wrote `status = LOCKED`. The 423 surface was wired to a door that never opened. This adds the missing half.

**Temporary, auto-expiring — not permanent.** A lock sets `status = LOCKED` plus `lockout_expires_at = now + lockout-duration` (default: 5 consecutive failures → a 15-minute window). `AuthServiceImpl.login` calls `releaseExpiredLock` *before* authenticating, so once the window elapses a correct password logs in normally and clears the counter. Permanent "contact support" lockout was rejected on purpose: it is a self-inflicted **denial-of-service vector** — anyone who knows a victim's email could lock them out at will by failing a few logins. **OWASP ASVS V2.2** and **NIST SP 800-63B §5.2.2** both prescribe throttling / temporary lockout over permanent. A `LOCKED` row with a *null* `lockout_expires_at` is reserved for a future permanent/administrative lock that never auto-releases — the two cases are distinguished by the presence of the expiry, at no extra cost.

**Two defences, two lifetimes.** This is the *persistent* second line behind the existing `AuthRateLimiter` (#18). The rate limiter is an in-memory token bucket — volatile (resets on restart), keyed by IP/email, refilled on a timer; it sheds volume cheaply. Account lockout is durable state on the `users` row that survives restarts and follows the account across rotating IPs. They are deliberately independent: a credential-stuffing wave trips the rate limit *and* leaves a forensic trail of locked accounts. (Driving the lockout from an HTTP test would actually be masked by the rate limiter — the per-email bucket returns 429 around the same count the lockout returns 423 — so `AccountLockoutIT` exercises the service directly, the same isolation `RefreshTokenReuseDetectionIT` uses.)

**Atomic SQL, no read-modify-write.** Every mutation in `LoginAttemptService` is a single statement: increment, conditional-lock-at-threshold, conditional-release-if-expired, conditional-reset-on-success. A read-then-write would let two concurrent failed logins read the same count and both write `n+1`, losing an increment — or fork the lock decision. Pushing the predicate into the `WHERE` clause (`… AND failed_login_attempts >= :max`, `… AND lockout_expires_at <= :now`) makes each operation race-safe without a pessimistic lock on the hot login path. An unknown email matches zero rows, so `recordFailure` is never an account-enumeration oracle — the client sees the same 401 whether or not the account exists.

**Counting only the right failures, and surviving the rollback.** The hook is the cause-split in `login`'s try/catch: only `BadCredentialsException` (a wrong password on an active account) feeds the counter; `LockedException`, `DisabledException` and the expiry exceptions do not, because they are not failed password guesses. The counter writes run in `REQUIRES_NEW` transactions, so the increment commits even though the surrounding login transaction unwinds with the `BadCredentialsException` it threw — the same isolation trick the idempotency reservation uses (#2/#4). Observability rides along: `paydude.auth.lockout` increments exactly when a lock is applied (#13) — the credential-stuffing signal for a Grafana panel — while the WARN log carries the policy values but no PII (no email, no id; the owner's identity belongs in an audit trail, not application logs).

**A latent bug the integration test caught.** Proving auto-unlock requires driving a login *to success* against a real database — and `AccountLockoutIT` was the first test in the project to do so (`AuthorizationIT` exercises only `/register`, `RefreshTokenReuseDetectionIT` calls the refresh service directly, `HttpStandardsIT` tests only failures). It immediately surfaced that `AuthServiceImpl.login` inherited the class-level `@Transactional(readOnly = true)` while writing a refresh-token row through `issueNewFamily` (propagation `REQUIRED`): every real successful login would have failed the INSERT on a read-only connection. The fix is the `@Transactional(rollbackFor = Exception.class)` the method was always missing — exactly the kind of defect a service-level IT exists to expose.

→ `LoginAttemptService` · `LoginAttemptServiceImpl` · `UserRepository` (lockout UPDATEs) · `AuthServiceImpl.login` · `SecurityProperties.Lockout` · `SecurityUser.isAccountNonLocked` · `V0_001__init_schema.sql` (lockout columns) · `LoginAttemptServiceImplTest` · `AccountLockoutIT`

### 23. A security audit log for the detection leg

PayDude's security surface was almost entirely *preventive* — layered rate limiting (#18), account lockout (#22), breach screening (#20), refresh-token rotation with reuse detection (#19). What it lacked was the *detection / forensics* leg: a durable, queryable record of **who attempted what**. Several of those events already happened and were even WARN-logged, but application logs are ephemeral, unstructured, and deliberately scrubbed of identifiers — useless for "show me every failed login against this account." The codebase had already reserved the seam: `V0_001`'s lockout comment defers a full per-attempt history to "the (separate) security audit log," and `LoginAttemptService` defers the account holder's identity to it. This pattern fills that seam, satisfying **OWASP ASVS V7** (security logging) and completing the story from *blocks attacks* to *blocks **and records** attacks*.

**A direct call in `REQUIRES_NEW`, not an event.** PayDude uses application events for decoupling elsewhere (`UserRegisteredEvent`, #4), so an event-driven audit listener was the obvious reach — and it is the wrong tool here. The events most worth capturing are *failures* — a wrong password, a locked account, a replayed refresh token — and each rolls its business transaction back. A `@TransactionalEventListener(AFTER_COMMIT)` never fires for a rolled-back transaction, so it would **silently drop exactly the events that matter most**. Instead `SecurityAuditService.record(...)` is called directly from the event sites and writes in a `REQUIRES_NEW` transaction — the same durability trick the lockout counters (#22) and the idempotency reservation (#2) use — so the row commits independently of the doomed login.

**Why the INSERT lives in its own bean.** Durability (`REQUIRES_NEW`) and fail-safe (a broken audit insert must never break the audited operation) cannot both live in one proxied method. A `REQUIRES_NEW` method commits when it *returns*, so even if it caught the persistence exception internally, the proxy's commit of the now-rollback-only transaction would still throw `UnexpectedRollbackException` into the caller. The fail-safe `try/catch` therefore has to sit *outside* the transactional proxy. Hence the split: `SecurityAuditWriter.write(...)` carries the `@Transactional(REQUIRES_NEW)`, and `SecurityAuditServiceImpl.record(...)` wraps the call to it in the `try/catch` that swallows any failure with an ERROR log — the same fail-open spirit as the breach check (#20). Recording must never be the reason a user can't log in.

**What is stored, and the PII judgment call.** Each row carries the event type, the outcome (`SUCCESS`/`FAILURE` — the same split as the `paydude.auth.login{outcome}` metric, #13), the `user_id` when known, the **attempted `principal`** (the login email), the request context (IP from `getRemoteAddr()` — `RemoteIpValve`-resolved in prod, never raw `X-Forwarded-For`; the User-Agent; and the W3C `traceId` from the MDC so a row links straight back to the request's logs, #12), and a short non-sensitive `detail`. Storing the attempted email is a deliberate inversion of the application-log discipline ("no identifiers in logs"): knowing *which account was targeted* is the entire forensic point, and the table is admin-only — a different threat model. Passwords, raw or hashed tokens, and full account numbers are **never** stored. `user_id` is a plain column with **no foreign key**: an audit trail must outlive the subject it describes, so a closed or deleted user must not cascade away the evidence.

**Read access is the first RBAC-gated API tier.** `GET /v1/admin/audit-events` (paginated, filterable by user / type / outcome, newest first) is restricted to `ROLE_ADMIN` — until now `ROLE_ADMIN` guarded only the Actuator chain (#16), so this is PayDude's first role-gated `/v1` endpoint. The matcher sits *above* the catch-all in `SecurityConfig` so it fails closed, and a normal user's valid token gets a `403` rendered through the same `ProblemDetail` path (#15) as every other error. This is the "protect access to the logs" half of ASVS V7.

**The trade-off: failure durability over success atomicity.** Because `record(...)` is uniformly `REQUIRES_NEW`, a `SUCCESS` event commits at the call site rather than atomically with the business transaction. For login / logout / password-change this is a non-issue (the call is the last step before the method returns); for `REGISTER` there is a narrow window where the default-account creation (a `BEFORE_COMMIT` listener, #4) could fail *after* the `REGISTER` row already committed. Strict success-atomicity would need an `AFTER_COMMIT` synchronisation — deliberately not adopted, because it would forfeit the failure-durability and fail-safe properties that are the whole point. Recording is gated by `application.security.audit.enabled` and bounded by a retention window the nightly `ExpiredDataCleanupJob` purges, so the table does not grow without bound.

→ `SecurityAuditService` · `SecurityAuditServiceImpl` · `SecurityAuditWriter` · `AuditContextResolver` · `SecurityAuditEvent` · `SecurityAuditEventRepository` · `AdminAuditController` · `SecurityConfig` (the `/v1/admin/**` matcher) · `ExpiredDataCleanupJob` (retention) · `V0_003__create_security_audit_events.sql` · `SecurityAuditServiceImplTest` · `AdminAuditControllerTest` · `SecurityAuditIT`

### 24. A TOTP second factor with a step-up login

A financial API whose strongest credential is a single password is one phishing email away from an account takeover; every regulator and framework that touches payments (PSD2's SCA, OWASP ASVS V2.8, NIST SP 800-63B AAL2) expects a second factor. This pattern adds **opt-in TOTP** (RFC 6238 over RFC 4226) end to end: enrollment, a step-up login, single-use recovery codes, and integration with the existing rate-limit (#18), lockout (#22) and audit (#23) layers — so the second factor arrives with its own brute-force story rather than as a checkbox.

**Implemented from the RFC, pinned by the RFC's own vectors.** TOTP is one `HmacSHA1` call plus the RFC 4226 §5.3 dynamic truncation — the only cryptographic primitive involved is the JDK's HMAC. Importing an OTP library would add a supply-chain dependency (which the DevSecOps pipeline would then scan forever) to avoid ~40 lines whose correctness the spec itself pins: `TotpServiceTest` asserts the **RFC 6238 Appendix B test vectors** verbatim, which is a stronger interoperability guarantee than any library README. The same reasoning produced the small RFC 4648 Base32 codec (`util/Base32`, pinned by the §10 vectors) — the JDK ships Base64 but not the Base32 the `otpauth://` ecosystem standardised on. Parameters are the authenticator-ecosystem defaults (SHA-1 · 6 digits · 30 s); advertising anything stronger breaks enrollment for apps that silently ignore the `algorithm` parameter.

**Enrollment is a two-phase commit, gated by the password.** `POST /v1/users/me/mfa/setup` generates the secret but arms nothing (`mfa_secret` set, `mfa_enabled` false); only `POST /v1/users/me/mfa/confirm` — by accepting a code the authenticator actually produced — flips the account to MFA-required. Skipping that proof would let a failed QR scan brick the account at its very next login. Setup and disable both demand the **account password**, not just the bearer token (the `ChangePasswordRequest` re-authentication rule, ASVS §2.4.5), because each is an account-takeover primitive on its own: with a stolen access token alone, an attacker could otherwise enroll *their* authenticator (locking the owner out) or strip the second factor off (downgrade). That password gate would itself be a brute-force oracle for a token holder, so all three endpoints are throttled per-user by `ReauthRateLimiter` (#18) — the side-door counterpart of the login throttle. `confirm` checks a TOTP code rather than the password, which is precisely why it shares the bucket: a 6-digit space is online-guessable, its wrong-code 409s feed no lockout, and the reward for a lucky guess is the recovery-code batch below. Confirm runs under a `PESSIMISTIC_WRITE` row lock (`UserRepository.findByIdForUpdate`) so two racing confirms cannot both pass the not-yet-enabled check and persist two batches of valid codes. It returns ten **single-use recovery codes** — shown once, stored as SHA-256 digests like refresh tokens (#19), redeemed by an atomic `used_at IS NULL` UPDATE so two redemptions of the same code cannot both win.

**The step-up: a typed challenge token, not half a session.** For an enrolled account, `login` returns no tokens — it returns a 5-minute **challenge JWT** (`MfaChallengeResponse`), and `AuthService.login`'s return type becomes the sealed `LoginResult` (`Tokens` | `MfaRequired`), so the controller's `switch` is exhaustive the same way `ReservationOutcome` (#2) is. The challenge is signed with the same key as access tokens but can never be confused with one: both kinds carry an explicit JOSE `typ` header (`at+jwt` per RFC 9068 for access tokens, `mfa+jwt` for challenges — RFC 8725 §3.11 explicit typing), and each parse path requires its own type. A stolen challenge presented as a Bearer dies in `JwtService.parseClaims` before any claim is read; an access token posted to `/v1/auth/mfa/verify` dies symmetrically. The challenge also carries no `status`/`role` claims — it authorizes nothing but a code attempt, and `verifyMfa` re-reads the account state from the database (five minutes is plenty of time to get locked).

**A 6-digit code is brute-forceable, so failures are first-class login failures.** The code space is 10⁶ with ~3 valid values inside the ±1-step skew window (RFC 6238 §5.2) — the one place in the auth surface where online guessing is arithmetically viable, made sharper by the fact that every caller already holds the password. Three controls bound it: `/v1/auth/mfa/verify` joins the IP filter's scope with its own strict bucket (policy `mfa`, advertising `RateLimit` headers like its siblings, #18); every wrong code feeds the **persistent lockout counter** exactly like a wrong password (#22) — and crucially, a correct password does *not* reset that counter while the second factor is pending, or each challenge cycle would hand the attacker a fresh budget; and verified codes are **single-use** (`mfa_last_used_step`, advanced by an atomic conditional UPDATE) so a shoulder-surfed code cannot be replayed even inside its validity window. Two transaction subtleties earned comments in the code: the step-consuming UPDATE runs `REQUIRES_NEW` so its row lock is released before `recordSuccess` (also `REQUIRES_NEW`, same row) runs — joined transactions would self-deadlock — and `confirm` seeds the baseline through the entity rather than the bulk UPDATE, because mixing a bulk write with a dirty entity lets Hibernate's all-columns flush clobber the column with a stale value.

**Observability and forensics ride along.** The password stage of an enrolled login writes an `MFA_CHALLENGE` audit row (#23); a challenge with no subsequent `LOGIN/SUCCESS` is the forensic signature of *a compromised password stopped by the second factor*. Completion writes `LOGIN/SUCCESS` with the factor in the detail (`mfa: totp` vs `mfa: recovery code` — a redeemed recovery code is worth noticing), enrollment transitions write `MFA_ENABLED`/`MFA_DISABLED`, and the `paydude.auth.mfa{outcome}` counter (#13) gives the Grafana panel its "correct passwords hitting a wall" signal. The TOTP secret itself is the one credential that **cannot be hashed** — the verifier must recompute the HMAC from it — so it is stored as the Base32 string with encryption-at-rest documented as the production hardening step (a KMS exercise, out of scope here), while everything else around it (recovery codes, refresh tokens) stays digest-only.

→ `TotpService` · `util/Base32` · `MfaService` / `MfaServiceImpl` · `MfaController` · `AuthServiceImpl.login` / `verifyMfa` · `LoginResult` · `JwtService` (typ-split mint/parse) · `IpRateLimitFilter` + `AuthRateLimiter.checkMfaVerifyByIp` · `MfaRecoveryCode` / `MfaRecoveryCodeRepository` · `UserRepository.markMfaStepUsed` · `SecurityProperties.Mfa` · `V0_004__add_totp_mfa.sql` · `TotpServiceTest` (RFC vectors) · `Base32Test` · `MfaServiceTest` · `MfaControllerTest` · `MfaLoginIT`
