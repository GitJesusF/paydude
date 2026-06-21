# PayDude — Financial Transactions API

![Java](https://img.shields.io/badge/java-21-blue)
![Spring Boot](https://img.shields.io/badge/spring%20boot-3.5-brightgreen)
![Coverage gate](https://img.shields.io/badge/coverage%20gate-%E2%89%A560%25%20line%20(enforced)-yellowgreen)
![CI](https://github.com/GitJesusF/paydude/actions/workflows/security.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

A concurrency-safe banking REST API in Spring Boot 3 / Java 21, built around **idempotent money movement**, **deadlock-free pessimistic locking**, and a standards-driven **stateless JWT security** stack — implementing the full Spring Security `UserDetails` contract end to end.

**What this demonstrates**

- **Concurrency-safe money movement** — idempotent deposits / withdrawals / transfers over pessimistic, deadlock-free row locking.
- **Production-grade auth & security** — JWT access + rotating refresh tokens with reuse detection, TOTP MFA built from RFC 6238, auto-expiring account lockout, and an append-only security audit trail.
- **Observability & DevSecOps** — Micrometer → Prometheus, W3C trace context in every log line, and SCA + SAST + SBOM + image scanning gated in CI.
- **Standards-driven** — patterns implemented against their source specs (RFC · NIST SP 800-63B · OWASP ASVS), cited inline rather than hand-waved.

**Contents:** [Highlights](#highlights) · [Tech stack](#tech-stack) · [Architecture](#architecture) · [Domain model](#domain-model) · [API](#api) · [Transfer flow](#transfer-flow) · [Running locally](#running-locally) · [Testing](#testing) · [Known limitations](#known-limitations) · [Project structure](#project-structure)

---

## Highlights

The engineering decisions worth a closer look — each links to its full write-up
(context → decision → trade-offs) in **[docs/patterns.md](docs/patterns.md)**:

- **[Deadlock-free transfers](docs/patterns.md#1-deadlock-free-pessimistic-locking)** — `SELECT … FOR UPDATE` in fixed alphabetical order, so A→B and B→A serialise instead of deadlocking.
- **[Idempotent money movements](docs/patterns.md#2-idempotent-money-movements-lookup-under-lock)** — reservation looked up under a `PESSIMISTIC_WRITE` lock and keyed on a SHA-256 of the canonical request; race-safe under concurrent duplicates, with expired keys reclaimed.
- **[Stateless JWT, full `UserDetails` contract](docs/patterns.md#5-complete-userdetails-contract)** — all four Spring Security state checks mapped to domain states; tokens rebuilt from claims with zero DB hits on the hot path.
- **[Rotating refresh tokens](docs/patterns.md#19-refresh-tokens-with-rotation-reuse-detection-and-family-based-revocation)** — opaque, single-use, family-revocable, with reuse detection (OAuth 2.1).
- **[Breached-password screening](docs/patterns.md#20-breached-password-screening-with-k-anonymity)** — HaveIBeenPwned k-anonymity, fail-open, per NIST SP 800-63B.
- **[Layered rate limiting](docs/patterns.md#18-layered-rate-limiting--infrastructure-tier-in-a-filter-business-tier-in-the-controller)** — per-IP auth throttles in a servlet filter, per-email login throttles in the controller, and per-user buckets for authenticated money-moving writes and the account-security management gates (change-password, MFA setup/confirm/disable).
- **[Account lockout](docs/patterns.md#22-account-lockout-that-completes-the-locked-state)** — temporary, auto-expiring lockout after N failed logins; the persistent second line behind rate limiting, completing the `LOCKED` state (OWASP ASVS V2.2 / NIST SP 800-63B §5.2.2).
- **[Security audit log](docs/patterns.md#23-a-security-audit-log-for-the-detection-leg)** — append-only trail of login / logout / register / password-change / lockout / token-reuse / MFA events, written in `REQUIRES_NEW` so it survives a failed login's rollback; read via an admin-only `ROLE_ADMIN` endpoint (OWASP ASVS V7).
- **[TOTP second factor](docs/patterns.md#24-a-totp-second-factor-with-a-step-up-login)** — opt-in MFA implemented from RFC 6238/4226 against the JDK's HMAC and pinned by the RFC's own test vectors; password-gated two-phase enrollment, a step-up login via an explicitly-typed challenge JWT (`at+jwt` vs `mfa+jwt`, RFC 8725/9068), single-use codes and hashed recovery codes, with wrong codes feeding the same lockout as wrong passwords.
- **[RFC 9457 Problem Details](docs/patterns.md#15-standardised-error-responses-with-rfc-9457-problem-details)** — one standard error shape; six per-concern advices with explicit `@Order`.
- **[Sealed types for domain outcomes](docs/patterns.md#21-sealed-outcome-types-for-branched-domain-operations)** — `IdempotentRequest` and `ReservationOutcome` turn a "can't-happen" branch into a compile error.
- **[Observability by default](docs/patterns.md#13-custom-business-metrics-behind-a-single-facade)** — Micrometer facade → Prometheus, W3C Trace Context in every log line, opt-in Grafana stack.
- **[Production-ready Actuator](docs/patterns.md#16-production-ready-actuator-surface-split-by-trust-tier)** — two security filter chains; public probes vs. an admin tier over HTTP Basic.
- **CI security pipeline (DevSecOps)** — every push/PR runs OWASP Dependency-Check (SCA), SpotBugs + FindSecBugs (SAST), a CycloneDX SBOM, and Trivy image scanning, gated to **fail on High+Critical** with a documented suppression file; findings flow to the GitHub Security tab as SARIF. Isolated in a `security` Maven profile, out of the default build.

**[→ Full catalog: all 24 patterns, in depth](docs/patterns.md)** — also covers the three purpose-built `ObjectMapper`s, event-driven rollback, the OAuth-style login/profile split, URI versioning, typed configuration, and the framework-agnostic pagination envelope.

> **Status:** deliberately over-built — each pattern is implemented against its source standard rather than to the minimum that "works." Not production-ready; the conscious trade-offs are catalogued under [Known limitations](#known-limitations).

---

## Tech stack

| Layer | Technology |
|---|---|
| Runtime | Java 21 |
| Framework | Spring Boot 3.5 |
| Security | Spring Security 6 + JWT (jjwt 0.13) + bucket4j 8 + Caffeine (rate limiting) |
| Persistence | PostgreSQL + Spring Data JPA + Flyway |
| Mapping | MapStruct 1.6 |
| API docs | SpringDoc OpenAPI 3 |
| Observability | Spring Boot Actuator + Micrometer (Prometheus registry) + Micrometer Tracing (W3C Trace Context, OTel bridge) + Logstash JSON encoder |
| Testing | JUnit 5 + Mockito + Testcontainers + Maven Surefire / Failsafe |
| Coverage | JaCoCo 0.8 (merged unit + integration, 60% line threshold enforced) |

---

## Architecture

> Formal architecture docs live in [`docs/architecture.md`](docs/architecture.md) — an
> [arc42](https://arc42.org)-structured write-up with embedded [C4](https://c4model.com) diagrams
> (Context → Container → Component → Dynamic). Canonical C4-PlantUML sources: [`docs/c4/`](docs/c4/).
> The quick view:

```
┌─────────────────────────────────────────────────────────────┐
│                        HTTP layer                           │
│  AuthController │ AccountController │ TransactionController │
└─────────────────────────┬───────────────────────────────────┘
                          │  @AuthenticationPrincipal SecurityUser
┌─────────────────────────▼───────────────────────────────────┐
│                      Service layer                          │
│  AuthService │ AccountService │ TransactionService          │
│  + IdempotencyKeyService  (REQUIRES_NEW)                    │
│       business logic · transaction boundaries               │
└──────┬───────────────┬─────────────────────┬────────────────┘
       │ publishes     │ Mapper + Assembler  │
       ▼               ▼                     ▼
┌────────────────────────┐   ┌─────────────┐   ┌────────────────┐
│       Listeners        │   │ Repositories│   │ DTOs (Records) │
│ AccountEventListener   │   │  + Flyway   │   │ sealed Idempo- │
│   (BEFORE_COMMIT)      │   │             │   │ tentRequest    │
│ IdempotencyCleanup     │   │             │   │                │
│   (AFTER_ROLLBACK)     │   │             │   │                │
└────────────────────────┘   └─────────────┘   └────────────────┘
```

**Key design choices**
- Service interfaces separated from implementations — clean seams for unit testing.
- Java Records for every DTO — immutable by design, no accidental mutation.
- `sealed interface IdempotentRequest` — the universe of idempotent operations is documented in a single `permits` clause, enforced at compile time.
- Mapper + Assembler split: MapStruct mappers handle plain entity→DTO; the assembler (`TransactionResponseAssembler`) handles entity→DTO when the result depends on the requesting user's perspective (SENT vs RECEIVED).
- `@Transactional(readOnly = true)` at class level, overridden per write method.
- `spring.jpa.open-in-view=false` — no lazy-loading surprises in the web layer.
- `@EnableJpaAuditing` lives in `JpaConfig` (not `Application`), so `@WebMvcTest` slices boot without JPA metamodel errors.

---

## Domain model

```
users
 └── accounts              (unique per user+currency; CHECK balance ≥ 0)
      ├── account_audits   (immutable; 1 row per balance change)
      └── transactions     (as source OR target; CHECK amount > 0, source ≠ target)
           └── account_audits  (linked for TRANSFER_IN / TRANSFER_OUT)

idempotency_keys           (unique per key_value+user_id; SHA-256 request hash)
refresh_tokens             (one row per session rotation; SHA-256 hash, family-revocable)
mfa_recovery_codes         (single-use, SHA-256 hash; CASCADEs with the user)
security_audit_events      (append-only; deliberately NO FK — the trail outlives its subject)
```

> Full data model — ER diagram, schema design decisions, concurrency/locking map, lifecycle and
> retention — in [`docs/data-model.md`](docs/data-model.md).

- All monetary values: `NUMERIC(19, 4)` — no floating-point rounding.
- Currency enum constrained at DB level: `USD`, `MXN`.
- Account statuses: `ACTIVE`, `PENDING`, `FROZEN`, `CLOSED`.
- User statuses: `ACTIVE`, `LOCKED`, `SUSPENDED`, `CLOSED` (`LOCKED` is set automatically by the anti-bruteforce lockout and auto-released after a cooldown).
- Idempotency key statuses: `PENDING → COMPLETED | FAILED`.

---

## API

Interactive docs: `http://localhost:8090/swagger-ui/index.html` when running locally.

All endpoints below are mounted under the `/v1` prefix — see [URI path versioning](docs/patterns.md#8-uri-path-versioning).

### Auth — public
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/auth/register` | Register user + open a default USD account |
| `POST` | `/v1/auth/login` | Authenticate. Single-factor accounts get the token response; MFA-enrolled accounts get a short-lived challenge (`mfaRequired: true`) instead |
| `POST` | `/v1/auth/mfa/verify` | Complete a step-up login: challenge token + 6-digit TOTP (or a recovery code) → token pair |
| `POST` | `/v1/auth/refresh` | Rotate a refresh token and receive a new token pair |
| `POST` | `/v1/auth/logout` | Revoke the presented refresh-token family |

**Auth response shape** (RFC 6749 §5.1)
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 900,
  "refreshToken": "ozzQ3hwmQ8Y3W1E...",
  "refreshExpiresIn": 604800
}
```

### Users — requires `Authorization: Bearer <token>`
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/users/me` | Authenticated user's profile (id, name, email, role, status) |
| `PATCH` | `/v1/users/me/password` | Change password and revoke all refresh-token families |
| `POST` | `/v1/users/me/mfa/setup` | Start TOTP enrollment (password-gated): returns the Base32 secret + `otpauth://` URI |
| `POST` | `/v1/users/me/mfa/confirm` | Prove the authenticator works; arms MFA and returns 10 single-use recovery codes |
| `POST` | `/v1/users/me/mfa/disable` | Remove the second factor (password-gated, idempotent) |
| `GET` | `/v2/users/me` | Versioned profile endpoint |

### Admin — requires `Authorization: Bearer <token>` with `ROLE_ADMIN`
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/admin/audit-events` | Paginated security audit trail; optional `userId` / `eventType` / `outcome` filters |

### Accounts — requires `Authorization: Bearer <token>`
| Method | Endpoint | Description |
|---|---|---|
| `GET`  | `/v1/accounts/me` | Current balance and status |
| `POST` | `/v1/accounts/deposit` | Deposit into own account; requires `Idempotency-Key` |
| `POST` | `/v1/accounts/withdraw` | Withdraw from own account; requires `Idempotency-Key` |
| `GET`  | `/v1/accounts/me/history` | Paginated audit of balance changes |

Headers for `POST /v1/accounts/deposit` and `POST /v1/accounts/withdraw`: `Authorization: Bearer <jwt>`, `Idempotency-Key: <uuid-v4>`.

### Transactions — requires `Authorization` + `Idempotency-Key`
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/transactions/transfer` | Transfer to another account |
| `GET`  | `/v1/transactions` | Paginated history (DESC by date) |

**Transfer request body**
```json
{
  "sourceAccountNumber": "4520000000000003",
  "targetAccountNumber": "4521111111111115",
  "amount": 100.00,
  "currency": "USD",
  "description": "Rent payment"
}
```
Headers: `Authorization: Bearer <jwt>`, `Idempotency-Key: <uuid-v4>`

**Transaction response**
```json
{
  "id": 42,
  "type": "SENT",
  "amount": 100.0000,
  "currency": "USD",
  "counterpartyName": "Maria Garcia",
  "counterpartyAccount": "****1115",
  "description": "Rent payment",
  "status": "COMPLETED",
  "date": "2026-04-20T21:00:00Z"
}
```

**Paginated endpoints** (`GET /v1/transactions`, `GET /v1/accounts/me/history`) return a `PagedResponse<T>` envelope — see [Framework-agnostic pagination envelope](docs/patterns.md#10-framework-agnostic-pagination-envelope) for the rationale.

---

## Transfer flow

```
POST /v1/transactions/transfer

 1. IdempotencyKeyService.reserveKey  (REQUIRES_NEW)
    ├─ Compute SHA-256(canonical JSON of operation scope + request) — fields sorted,
    │  BigDecimal trailing zeros stripped, description excluded via mix-in
    └─ SELECT existing (key_value, user_id) FOR UPDATE, then branch:
         · expired   → reclaim in place as a fresh PENDING reservation
         · COMPLETED → return the cached response (no re-processing)
         · FAILED    → reject, ask caller for a new key
         · PENDING   → reject, already in progress
       If no row exists, INSERT a fresh PENDING reservation.
 2. Publish IdempotencyKeyReservedEvent
 3. Validate request-only invariants
    (currency code exists; source and target already differ by DTO construction)
 4. Acquire PESSIMISTIC_WRITE locks in alphabetical order of account_number
    ← deadlock prevention
 5. Validate post-lock invariants with fresh data
    (source belongs to caller, both accounts ACTIVE, same currency,
     request currency matches source account, sufficient funds)
 6. Update both balances
 7. Persist Transaction (COMPLETED) + 2 AccountAudit records
    (TRANSFER_OUT on sender, TRANSFER_IN on target)
 8. Serialise the response → save into IdempotencyKey (status = COMPLETED)

If the outer transaction rolls back at any point:
  IdempotencyCleanupListener.releaseKeyOnFailure (AFTER_ROLLBACK, REQUIRES_NEW)
  flips the key from PENDING to FAILED in a new transaction.
```

`POST /v1/accounts/deposit` and `POST /v1/accounts/withdraw` use the same idempotency lifecycle:
reserve key in `REQUIRES_NEW`, publish `IdempotencyKeyReservedEvent`, lock the user's account,
apply the balance mutation, persist the audit row, cache the `AccountResponse`, then replay that
cached response on duplicate requests. Their operation scopes are `accounts.deposit` and
`accounts.withdraw`, so one endpoint cannot replay the other's result under the same key.

---

## Running locally

### Quickstart

A **Makefile is the single front door** — run `make` (or `make help`) to list every task. The everyday ones:

```bash
make dev        # App on your JVM + Dockerized Postgres (dev profile, Swagger at :8090)
make obs        # Full stack in Docker + Grafana/Loki/Prometheus dashboards (Grafana at :3000)
make test       # Fast unit tests (no Docker)
make verify     # Unit + integration tests + coverage (needs Docker)
make security   # DevSecOps scans: SCA + SAST + SBOM
make down       # Stop everything
```

`make dev` wraps [`scripts/dev.sh`](scripts/dev.sh), which brings up Postgres, waits for it to pass its healthcheck, then starts the app — surfacing the common "Docker daemon down / port 5432 taken / container unhealthy" failures up front instead of behind a generic error. The sections below document what each target runs under the hood, plus the manual and production-overlay commands for finer control.

### Prerequisites
- Java 21
- Docker + Docker Compose — runs Postgres for `make dev`, the Docker modes, and the integration tests
- GNU Make — optional; drives the shortcuts above (each maps to a plain command you can run directly)
- PostgreSQL 14+ — only if you point the app at a local database instead of the Dockerized one (see Setup)

### Setup

1. Create the database:
   ```sql
   CREATE DATABASE paydude_db;
   ```
2. Export the required environment variables (no defaults are baked in for secrets):
   ```bash
   export DB_PASSWORD=<your-postgres-password>
   export JWT_SECRET_KEY=<base64-encoded-256-bit-secret>
   ```
   `DB_URL` and `DB_USERNAME` default to `jdbc:postgresql://localhost:5432/paydude_db` and `postgres`; override them if your local setup differs.

3. Run — Flyway applies the schema on first boot:
   ```bash
   ./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
   ```
   The app listens on port **8090**. Open `http://localhost:8090/swagger-ui/index.html` to explore the API.

### Running with Docker

Four compose layouts cover the lifecycle from inner dev loop to production-hardened deploy. All of them auto-load the project-root `.env` (start by copying `.env.example`). The `make dev`, `make up`, and `make obs` shortcuts (see [Quickstart](#quickstart)) wrap the dev-loop, **Production-shaped**, and **+ Observability** rows; the production-hardened overlay stays an explicit command, since it's a deploy step rather than a daily task.

| Mode | Command | What runs | When to use |
|------|---------|-----------|-------------|
| **Dev DB only** | `docker compose -f docker-compose.db-only.yml up -d` | Postgres only | You want the app on your local JVM (`./mvnw spring-boot:run -Dspring-boot.run.profiles=dev`) for hot reload and IDE debugging. The `spring-boot-docker-compose` integration in `pom.xml` will also start this file automatically when the dev profile is active. The `.db-only` suffix (rather than `.dev`) is deliberate: this file is **not** a compose overlay on top of `docker-compose.yml`, it's a standalone single-service file, and the name should reflect that. |
| **Production-shaped** | `docker compose up -d` | Postgres + app, `prod` profile | Local end-to-end smoke test of the production behaviour (JSON logs, no Swagger UI, narrow Actuator surface, `health.show-details=when-authorized`). Convenience JWT/DB defaults are baked in so a fresh clone runs without editing anything. |
| **Production-hardened** | `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` | Postgres + app, `prod` profile, with all the hardening in [`docs/deployment.md`](docs/deployment.md) | Single-host bare-metal Docker deployment, or as a faithful reference when porting to Kubernetes / ECS / Fargate. |
| **+ Observability** | `docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d` | Adds Prometheus + Loki + Promtail + Grafana | Watching the [RED-method dashboard](docs/patterns.md#17-self-contained-local-observability-stack) live while exercising the API. Stackable with the prod overlay if you really want both. |

#### Production hardening

`docker-compose.prod.yml` hardens the base image along seven axes — mandatory (fail-fast) secrets, an unpublished DB port, resource limits, signal handling for graceful shutdown, log rotation, least privilege (`cap_drop: [ALL]`, non-root), and an immutable rootfs — on top of a multi-stage, non-root, layered-JAR image with an in-image readiness `HEALTHCHECK`.

**Full breakdown — each override and why it matters: [`docs/deployment.md`](docs/deployment.md).**

---

Tests are split between **Surefire** (`*Test.java` — unit, fast) and **Failsafe** (`*IT.java` — integration, Testcontainers PostgreSQL). Run with:

```bash
./mvnw test               # Unit tests only — fast, no Docker
./mvnw verify             # Unit + integration tests + JaCoCo coverage report
./mvnw verify -DskipITs   # Skip integration tests but still emit the JaCoCo report
```

Coverage report lives at `target/site/jacoco/index.html` after `mvn verify`. The build fails if line coverage drops below 60% (configured threshold; current baseline 65%).

---

## Testing

The test layout enforces a separation that matters at scale:

```
src/test/java/com/jesusf/paydude/
├── support/                        Shared test infrastructure
│   ├── TestcontainersConfiguration   PostgreSQLContainer + @ServiceConnection
│   ├── TestPayDudeApplication        Alternate main: bootRun with TC attached
│   ├── WithMockSecurityUser          Custom annotation for controller tests
│   └── WithMockSecurityUserFactory   Factory consumed by @WithSecurityContext
├── PayDudeApplicationIT            Smoke IT: full context + Flyway against TC
├── concurrency/                    ITs specific to concurrency (Loom + locking)
└── (per-package unit tests)        Mirrors src/main package structure

src/test/resources/
└── application-test.properties     Activated via @ActiveProfiles("test")
```

**Test categories** (383 unit tests, 30 integration tests):

| Type | Tooling | Scope |
|------|---------|-------|
| Service | `@ExtendWith(MockitoExtension.class)` | Business logic in isolation |
| Security | Plain JUnit + `ReflectionTestUtils` | JWT round-trip without Spring |
| Controller | `@WebMvcTest` + `addFilters = false` | HTTP layer with mocked services |
| Config slice | `@SpringJUnitConfig` | Bean wiring without full app boot |
| Integration (`*IT`) | `@SpringBootTest` + Testcontainers | End-to-end flow with real Postgres |

**The `support/` package** isolates shared infrastructure (`TestcontainersConfiguration`, `WithMockSecurityUser`) from the tests themselves. Without it, helpers and tests sit side-by-side at the package root and the IDE explorer can't tell them apart.

**The `test` profile** (`application-test.properties`) replaces the dev profile during ITs: stable JWT key, `spring.docker.compose.enabled=false` to avoid colliding with Testcontainers, springdoc disabled for faster startup, quieter Hibernate logging. The datasource is provided at runtime by `@ServiceConnection` on the `PostgreSQLContainer` bean — never hardcoded.

**JaCoCo coverage** is merged across Surefire and Failsafe via the `merge` goal so a single report covers both unit and integration paths. Exclusions (DTOs, entities, mappers, enums, events, `Application.class`) keep the percentage focused on code with real branching logic. The `check` goal enforces a 60% line coverage minimum and fails the build below that.

---

## Known limitations

Scoped out of this project but worth calling out:

- **Secrets management.** Connection strings and the JWT secret are read from environment variables in both profiles. Local `application-dev.properties` provides defaults only for the DB URL and username; the password and JWT secret must always come from the environment.
- **Auth hardening.** Rate limiting is layered by abuse key: public token endpoints get per-IP buckets, login also gets a canonical-email bucket, and authenticated money-moving writes and the account-security management gates (change-password, MFA setup/confirm/disable) get per-user buckets (see [pattern 18](docs/patterns.md#18-layered-rate-limiting--infrastructure-tier-in-a-filter-business-tier-in-the-controller)), with the public token endpoints advertising IETF `RateLimit` headers (`draft-ietf-httpapi-ratelimit-headers`) so clients back off proactively; consecutive failed logins temporarily lock the account, completing the `LOCKED` state (see [pattern 22](docs/patterns.md#22-account-lockout-that-completes-the-locked-state)); accounts can opt into a TOTP second factor (RFC 6238) with a step-up login, single-use recovery codes, and wrong codes counting toward the same lockout (see [pattern 24](docs/patterns.md#24-a-totp-second-factor-with-a-step-up-login)); every security-relevant event (login success/failure, logout, registration, password change, lockout, token reuse) is appended to a durable, admin-readable audit trail, written in `REQUIRES_NEW` so a failed login's row survives its own rollback (see [pattern 23](docs/patterns.md#23-a-security-audit-log-for-the-detection-leg)); refresh tokens with rotation and reuse detection are wired (see [pattern 19](docs/patterns.md#19-refresh-tokens-with-rotation-reuse-detection-and-family-based-revocation)); the password policy follows NIST SP 800-63B §5.1.1.2 (8–64 length, no composition rules, HaveIBeenPwned breach screening, no forced rotation); CORS, the RFC 6750 Bearer challenge, RFC 9111 cache headers and the OWASP secure-header baseline are configured in `SecurityConfig` (see [`docs/standards.md`](docs/standards.md)).
- **Edge controls.** Application-level write throttling is keyed by authenticated user id. Coarse per-IP flood protection for every path is intentionally left to the deployment edge (reverse proxy, WAF, cloud load balancer), where it can reject traffic before it reaches the JVM.
- **Idempotency after a crash.** If the JVM dies between reserving an idempotency key and resolving it, the key stays `PENDING` (retries answer "operation in progress") until its TTL reclaims it. A stale-`PENDING` reclaim heuristic is deliberately not implemented — it cannot distinguish a crashed attempt from one still executing, and guessing wrong would re-run a money movement. Clients recover by retrying with a fresh key.
- **Currency.** Schema supports `USD` and `MXN` but there is no FX conversion — cross-currency transfers are rejected.

---

## Project structure

```
src/main/java/com/jesusf/paydude/
├── assembler/   TransactionResponseAssembler (entity → DTO with caller context)
├── config/      JpaConfig, OpenApiConfig, IdempotencyConfig (canonical mapper), WebConfig
│   ├── mixin/      Per-DTO Jackson mix-ins for hashing rules
│   ├── properties/ Typed @ConfigurationProperties records
│   └── web/        @ApiV1 / @ApiV2 markers (URI path versioning)
├── controller/  Auth, Account, Transaction, User, Mfa (TOTP enrollment),
│                AdminAudit (admin-only audit reads)
├── dto/         Records — auth/, account/, transactions/, user/, audit/
│   └── idempotent/ sealed interface IdempotentRequest + its permitted DTOs
│                   (TransferRequest, AccountOperationRequest) — co-located because
│                   sealed permits must share a package in the unnamed module
│                + PagedResponse&lt;T&gt; (framework-agnostic page envelope)
├── entity/      User, Account, Transaction, AccountAudit, IdempotencyKey, RefreshToken,
│                SecurityAuditEvent (append-only security event trail),
│                MfaRecoveryCode (hashed single-use recovery codes)
├── enums/       Role, UserStatus, AccountStatus, TransactionStatus, TransactionType,
│                Currency, AuditAction, IdempotencyKeyStatus,
│                SecurityAuditEventType, SecurityAuditOutcome
├── event/       UserRegisteredEvent, IdempotencyKeyReservedEvent
├── listener/    AccountEventListener (BEFORE_COMMIT),
│                IdempotencyCleanupListener (AFTER_ROLLBACK)
├── exception/   Domain exceptions (BusinessException, ResourceNotFoundException,
│                RateLimitExceededException) + per-concern @RestControllerAdvice
│                classes (Validation, Security, Business, Persistence, RateLimit,
│                Root) with explicit @Order precedence + ErrorResponses helper
├── mapper/      MapStruct mappers (User, Account, Transaction, AccountAudit)
├── repository/  JPA repositories with pessimistic-lock queries
├── security/    JwtAuthenticationFilter, JwtService, JwtClaimNames, SecurityConfig,
│   │            SecurityUser, CustomUserDetailsService, CustomSecurityExceptionHandler,
│   │            BreachedPasswordGuard (HaveIBeenPwned screening),
│   │            TotpService (RFC 6238, pinned by the RFC's test vectors)
│   └── ratelimit/ IpRateLimitFilter (infra tier), AuthRateLimiter, WriteRateLimiter,
│                ReauthRateLimiter (bucket4j + Caffeine business tiers)
├── service/     Service interfaces + Impl classes (Auth, User, Account, Transaction,
│                IdempotencyKey, RefreshToken — rotation + reuse detection,
│                SecurityAudit — append-only audit trail, LoginAttempt — lockout,
│                Mfa — TOTP enrollment lifecycle + code verification)
├── util/        AccountNumberGenerator (16-digit Luhn-checked numbers),
│                AccountNumberMasker, Base32 (RFC 4648, for the TOTP secret)
└── validation/  @MaxByteLength and @AccountNumber custom constraints
```

---

## Author

**Jesus Obregon** — PayDude takes a realistic banking domain and implements concurrency control, Spring Security, and observability patterns against their source standards (RFC · NIST · OWASP), rather than to the minimum that ships.

**Contact** — [GitHub](https://github.com/GitJesusF) · [LinkedIn](https://www.linkedin.com/in/jesus-obregon-a365ab22a/)
