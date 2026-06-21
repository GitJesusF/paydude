# Standards & Specifications in PayDude

This document explains **what** the standards PayDude cites in its code and documentation are,
**which ones it already uses**, and **which it could adopt** to raise the project's quality. It's
written so that someone seeing these acronyms (RFC, NIST, OWASP, ISO…) for the first time can
understand and defend each decision on its merits, without studying them from scratch.

**Why they matter.** Following a standard instead of inventing a solution has three concrete advantages:

1. **You don't reinvent an already-solved problem** — people with more context than you already thought through the edge cases.
2. **Interoperability** — a client that understands `application/problem+json` understands your errors without reading your documentation.
3. **Auditability** — "we did it this way because NIST SP 800-63B recommends it" is an answer; "we did it this way because it felt right" is not.

---

## 1. The map: who publishes the standards

Before the catalog, it helps to know which body publishes what, because each has a distinct tone and scope.

| Body | What it publishes | Tone | Example in PayDude |
|-----------|-------------|------|--------------------|
| **IETF** (Internet Engineering Task Force) | **RFC** (*Request for Comments*) — specifications of Internet protocols. Numbered; a new RFC can *obsolete* another. | Normative and precise (`MUST`, `SHOULD`, `MAY` have formal meaning — RFC 2119). | RFC 9457 (Problem Details), RFC 6749 (OAuth 2.0). |
| **NIST** (National Institute of Standards and Technology, USA) | **Special Publications (SP)** — security and cryptography guidance. Also **FIPS** (mandatory federal standards). | Reasoned, evidence-reviewed recommendations. | NIST SP 800-63B (digital identity), FIPS 180-4 (SHA-2). |
| **ISO / IEC** | International standards for *everything* — date formats, currency codes, card numbering. Paywalled (the documents cost money), but the rules are public-domain. | Formal, neutral, cross-industry. | ISO 8601 (dates), ISO 4217 (currencies), ISO/IEC 7812 (account/card numbering). |
| **OWASP** (Open Worldwide Application Security Project) | Application-security guidance. **ASVS** (*Application Security Verification Standard*) is a verifiable checklist; the **Top 10** is awareness material. Non-profit, community-driven. | Practical, oriented to "what to verify". | OWASP ASVS v4 §2.4.5 (session management). |
| **W3C** | Web standards (HTML, CORS, Trace Context). | Normative, browser- and web-oriented. | Trace Context (`traceparent`) — see §2.4. |

> **Careful with the word "standard".** Not everything that looks like a standard is one. Stripe's
> *Idempotency-Key convention* is a widespread industry pattern, but it is **not** an RFC (yet — see
> §3.2). The observability **RED method** is a methodology, not a specification. This document
> explicitly flags what is convention rather than a formal standard.

---

## 2. Standards PayDude already uses

### 2.1 Security and authentication

#### JWT — RFC 7519, with RFC 7515 (JWS) and RFC 2104 (HMAC)

- **What it is.** RFC 7519 defines the *JSON Web Token*: a container of "claims" (assertions) in JSON, base64url-encoded and **signed**. The signature is defined by RFC 7515 (*JSON Web Signature*); PayDude uses the `HS256` algorithm, which is HMAC-SHA256 — the HMAC itself is defined by RFC 2104.
- **Where in PayDude.** `JwtService` issues and verifies tokens; `sub` mirrors `userId`, and `JwtClaimNames` centralizes the custom claim names (`userId`, `role`, `status`, …). The `jjwt` library implements all three RFCs for us.
- **Why.** The access token is *stateless*: the server rebuilds the `SecurityUser` from the signed claims without touching the DB. The HMAC signature guarantees the client could not have altered the payload.

#### OAuth 2.0-style login response — RFC 6749 §5.1

- **What it is.** RFC 6749 defines the OAuth 2.0 framework. Section §5.1 fixes the core shape of a token response: `access_token`, `token_type`, `expires_in`; refresh-capable flows add a refresh token alongside the access token.
- **Where in PayDude.** `POST /v1/auth/login`, `POST /v1/auth/register` and `POST /v1/auth/refresh` return token-pair fields (`accessToken`, `tokenType: "Bearer"`, `expiresIn`, `refreshToken`, `refreshExpiresIn`) and **no profile data**. The profile lives at `GET /v1/users/me`.
- **Why.** A client that already speaks OAuth (most SDKs) understands the response without adapting it. Separating token from profile keeps the JWT free of PII.

#### Refresh-token rotation with reuse detection — RFC 9700 (OAuth 2.1 BCP)

- **What it is.** RFC 9700 ("OAuth 2.0 Security Best Current Practice", the basis for OAuth 2.1) **mandates** that refresh tokens for public clients be *single-use* and rotated, and that reuse of an already-rotated token be treated as compromise.
- **Where in PayDude.** `RefreshTokenServiceImpl.rotate()`: each `/refresh` revokes the presented token and issues a new one in the same *family*; presenting an already-revoked token triggers `revokeFamily(...)`.
- **Why.** It shrinks the blast radius of a stolen refresh token from "until its natural expiry" to "until the legitimate user next refreshes" — usually minutes.

#### Token revocation — RFC 7009

- **What it is.** RFC 7009 ("OAuth 2.0 Token Revocation") defines the `/revoke` endpoint for invalidating a token before its natural expiry. §2.2 mandates that invalid tokens (unknown, already revoked, malformed) **not** produce an error response — the client cannot recover from a revocation error, and distinguishing valid from invalid tokens would turn the endpoint into a validity oracle for enumeration.
- **Where in PayDude.** `POST /v1/auth/logout` revokes the entire *family* of the presented refresh token. Any token — valid, unknown, or already revoked — returns `204 No Content` (the RFC prescribes `200`; we use `204` for consistency with the rest of the API, which reserves `204` for body-less responses — the idempotent behaviour the RFC asks for is preserved). The endpoint is **not** rate-limited: throttling logout would let an attacker who exhausted the user's bucket prevent them from closing a compromised session.
- **Why.** Without explicit revocation, a stolen refresh token lives until its natural expiry (7 days). With `/logout` the blast radius closes at the user's pace, not the clock's — and the silence toward invalid tokens closes the enumeration vector the RFC explicitly anticipates.

#### Bearer-token challenge — RFC 6750 §3

- **What it is.** RFC 6750 defines how a Bearer token is used over HTTP. §3 fixes that a `401` to a protected resource **must** carry a `WWW-Authenticate: Bearer` header — the *challenge* that tells the client how to authenticate. When the presented token is rejected, the challenge is refined to `Bearer error="invalid_token"`.
- **Where in PayDude.** `CustomSecurityExceptionHandler.commence()` emits the bare challenge when no token arrived; `JwtAuthenticationFilter.forwardAuthFailure(...)` emits `error="invalid_token"` when the presented token failed with a 401 (signature, expiry, account/credential expiry). The disabled (403) and locked (423) refusals deliberately carry **no** challenge: `WWW-Authenticate` is the 401 contract ("authenticate, then retry"), and re-authenticating cannot cure those states.
- **Why.** A generic OAuth client distinguishes "I'm missing a credential" from "my credential no longer works, re-authenticate" without parsing the body.

#### UUID — RFC 9562 (obsoletes RFC 4122)

- **What it is.** Defines the format of the *Universally Unique Identifier*: 128 bits, canonical `8-4-4-4-12` hex representation. Version 4 is random.
- **Where in PayDude.** The `Idempotency-Key` header is validated with a UUID `@Pattern`; the refresh tokens' `family_id` is a UUID. (The W3C Trace Context `traceId` — see §2.4 — uses its own 128-bit format, not UUID.)
- **Why.** It provides uniqueness without central coordination — the client can generate the key without asking the server anything.

#### base64url — RFC 4648 §5

- **What it is.** RFC 4648 defines the Base16/32/64 encodings. The **url-safe** variant (§5) replaces `+` and `/` with `-` and `_`, so the value travels in a URL or header without escaping.
- **Where in PayDude.** The refresh token (32 bytes of `SecureRandom`) is transported as base64url. JWTs also use base64url internally.

#### Private IP ranges — RFC 1918

- **What it is.** Reserves the ranges `10/8`, `172.16/12`, `192.168/16` for private networks (not routable on the public Internet).
- **Where in PayDude.** Tomcat's `RemoteIpValve` (active in `prod`) only unwraps `X-Forwarded-For` when the TCP peer falls within RFC 1918 + loopback. `IpRateLimitFilter` trusts `getRemoteAddr()` after that filtering.
- **Why.** If you trusted `X-Forwarded-For` without verifying the peer, anyone could forge their IP and evade the rate limit.

#### Password policy — NIST SP 800-63B §5.1.1.2

- **What it is.** NIST's digital-identity guidance. §5.1.1.2 ("Memorized Secret Verifiers") fixes how a system should validate the passwords a user chooses: minimum length of 8 with support for **at least 64** characters, **no** arbitrary composition rules, **rejecting** those that appear in known breach corpora, and **no** forced periodic rotation — the classic "change your password every 90 days" worsens security because users pick predictable, incremental variants.
- **Where in PayDude.** All four rules are implemented:
  - **Length 8–64** — `@Size(min = 8, max = 64)` on `RegisterRequest` and `ChangePasswordRequest`. The 64 ceiling satisfies NIST's "at least 64" and conveniently stays under BCrypt's 72-byte limit, avoiding silent hash truncation.
  - **No composition rules** — there is no `@Pattern` on the password field, by design: NIST explicitly discourages uppercase/digit/symbol requirements.
  - **Breached-password rejection** — `BreachedPasswordGuard` queries the HaveIBeenPwned corpus at registration and password change, via k-anonymity (only the first 5 hex of the SHA-1 digest leave the JVM, never the password). *Fail-open* policy: an API outage skips the check rather than blocking the user. Per-profile toggle via `application.security.password.breach-check-enabled`.
  - **No forced rotation** — credential rotation is **disabled by default**; it is opt-in via `application.security.credentials-expiration-days` only for environments with legacy compliance that requires it.
- **Why.** Follow the evidence, not the habit. Each rule is defensible precisely because it cites the source.

#### Account lockout / authentication throttling — OWASP ASVS V2.2 + NIST SP 800-63B §5.2.2

- **What it is.** Both standards require *limiting authentication attempts* to resist online brute-force and credential stuffing. NIST SP 800-63B §5.2.2 ("Rate Limiting / Throttling") says verifiers SHALL limit the number of consecutive failed attempts; OWASP ASVS V2.2 verifies anti-automation controls are present. Both favour *temporary* lockout/throttling over *permanent* lockout — a permanent lock is itself a denial-of-service vector, since an attacker can lock a victim out just by knowing their username.
- **Where in PayDude.** Two layers, by design. `AuthRateLimiter` (in-memory, per-email token bucket) sheds volume cheaply. `LoginAttemptService` adds the *persistent* control: after `application.security.lockout.max-attempts` consecutive failures it transitions the account to `UserStatus.LOCKED` for `lockout-duration`, enforced by `SecurityUser.isAccountNonLocked()` (HTTP 423) and auto-released once the window elapses. Pinned by `AccountLockoutIT` (threshold → 423 → auto-unlock) and `LoginAttemptServiceImplTest`.
- **Why.** Follow the standards' explicit guidance — limit attempts, but *temporarily*, so a legitimate user is never permanently denied access by someone else's failed guesses, and every lock leaves an auditable trail (`paydude.auth.lockout`). Detail: [`docs/patterns.md` #22](patterns.md#22-account-lockout-that-completes-the-locked-state).

#### TOTP second factor — RFC 6238 / RFC 4226 · NIST SP 800-63B AAL2 · OWASP ASVS V2.8

- **What they are.** RFC 4226 (*HOTP*) defines one-time passwords derived from an HMAC over a counter; RFC 6238 (*TOTP*) makes the counter time-based (30-second steps) — the algorithm behind Google Authenticator and every compatible app. NIST SP 800-63B classifies an OTP device as a second authentication factor (AAL2 requires two factors); OWASP ASVS V2.8 sets the verification rules for one-time verifiers — including that codes be single-use and that a lost-device recovery path exist without weakening the scheme.
- **Where in PayDude.** `TotpService` implements RFC 6238 over the JDK's `HmacSHA1`, pinned by the **RFC 6238 Appendix B test vectors** in `TotpServiceTest`; the shared secret travels as an `otpauth://` URI with the secret in Base32 (**RFC 4648 §6**, implemented in `util/Base32`, pinned by the §10 vectors). Enrollment (`/v1/users/me/mfa/setup` + `/confirm`) is password-gated and two-phase; login becomes a step-up (`LoginResult.MfaRequired` → `POST /v1/auth/mfa/verify`); verified codes are single-use (RFC 6238 §5.2 — `mfa_last_used_step` advanced by an atomic conditional UPDATE), wrong codes feed the persistent lockout (V2.2) and the per-IP `mfa` bucket, and ten single-use SHA-256-hashed recovery codes cover the lost-device path.
- **Why.** A password-only financial API fails AAL2 and every payments-adjacent expectation (PSD2 SCA). Implementing the RFC directly — with the RFC's own answer key as the test — keeps the supply chain clean and the interoperability provable. Detail: [`docs/patterns.md` #24](patterns.md#24-a-totp-second-factor-with-a-step-up-login).

#### Explicit JWT typing — RFC 9068 / RFC 8725 §3.11

- **What they are.** RFC 8725 (*JWT Best Current Practices*) §3.11 mandates that different token kinds sharing a key be made mutually unconfusable via explicit typing; RFC 9068 registers the `at+jwt` JOSE `typ` for OAuth access tokens.
- **Where in PayDude.** `JwtService` brands access tokens `typ: at+jwt` and MFA challenge tokens `typ: mfa+jwt`, and each parse entry point (`parseClaims` for the Bearer path, `parseMfaChallengeClaims` for `/v1/auth/mfa/verify`) requires its own type before reading a single claim.
- **Why.** Both token kinds are HMAC-signed with the same key. Without the `typ` split, an intercepted 5-minute challenge token (proof of *half* an authentication) would verify as a full access token — a token-confusion escalation the header check kills at parse time.

#### Security logging — OWASP ASVS V7

- **What it is.** OWASP ASVS V7 ("Error Handling and Logging") requires that security-relevant events be logged with enough context to investigate an incident, that the log be protected from unauthorised access, and that secrets (passwords, session tokens) are never written to it.
- **Where in PayDude.** `SecurityAuditService` appends an immutable row to `security_audit_events` for every login (success/failure), logout, registration, password change, account lockout and refresh-token reuse — capturing the event type, outcome, the affected `user_id` and/or the *attempted* principal, the request IP, User-Agent and W3C `traceId`, but never a password or token. The write runs in a `REQUIRES_NEW` transaction so a failed login's row survives the login's own rollback, and is fail-safe so a logging error never breaks the audited operation. The trail is readable only by `ROLE_ADMIN`, via `GET /v1/admin/audit-events`.
- **Why.** The prevention controls (rate limiting, lockout, breach screening, token rotation) *stop* attacks; ASVS V7 is the *detection* counterpart — without a durable, queryable, access-controlled record you cannot answer "who attempted what". Detail: [`docs/patterns.md` #23](patterns.md#23-a-security-audit-log-for-the-detection-leg).

#### Session management — OWASP ASVS v4 §2.4.5

- **What it is.** ASVS is a security-verification checklist. §2.4.5 requires that changing the password invalidate the user's other active sessions.
- **Where in PayDude.** `PATCH /v1/users/me/password` calls `refreshTokenService.revokeAllForUser(userId)` after verifying the current password.
- **Why.** If your account is stolen and you change the password, the attacker must not stay in with an old refresh token.

#### API resource consumption and sensitive business flows — OWASP API4/API6:2023

- **What it is.** OWASP API4:2023 ("Unrestricted Resource Consumption") treats missing or poorly tuned limits as an API risk: requests consume CPU, memory, storage and downstream capacity, and the protection has to be tuned to the endpoint's business cost. OWASP API6:2023 ("Unrestricted Access to Sensitive Business Flows") covers excessive automated use of workflows that are legitimate one call at a time but harmful at scale.
- **Where in PayDude.** `IpRateLimitFilter` applies cheap per-IP buckets to public token endpoints before Spring Security. `AuthRateLimiter` adds a canonical-email bucket for login failures. `WriteRateLimiter` applies a per-authenticated-user bucket to `POST /v1/accounts/deposit`, `POST /v1/accounts/withdraw` and `POST /v1/transactions/transfer`, before service or database work. The write bucket protects the rows and locks that are expensive for this domain: `idempotency_keys`, `transactions`, `account_audits` and `accounts` `PESSIMISTIC_WRITE` locks. `ReauthRateLimiter` adds a per-authenticated-user bucket to the password re-authentication gates — `PATCH /v1/users/me/password` and `POST /v1/users/me/mfa/{setup,disable}` — which re-verify the account password behind a bearer token but sit outside the IP and email tiers.
- **Why.** The key follows the abuse model. Public auth endpoints are keyed by IP because there is no trusted principal yet; login is also keyed by email because credential stuffing targets an account identifier; authenticated money-moving writes are keyed by user id because the caller is known, rotating IPs must not reset the budget, and unrelated users behind one NAT must not share it. The password re-auth gates are keyed by user id for the same reason, and throttled (a 429, not the account lockout) so a stolen token cannot brute-force the account password through them while the legitimate owner can still log in to revoke the session. Coarse per-IP flood control for every path belongs at the edge (reverse proxy, WAF or cloud load balancer), where it can stop traffic before the JVM.

#### SHA-256 — FIPS 180-4

- **What it is.** FIPS 180-4 (*Secure Hash Standard*) defines the SHA-2 family, including SHA-256: a 256-bit hash function.
- **Where in PayDude.** Hash of the canonical JSON for the idempotency `request_hash`; hash of the refresh token before persisting it (`token_hash`).
- **Why.** For idempotency: structural uniqueness. For the refresh token: a DB leak yields no usable tokens, only their digests.

### 2.2 HTTP and API contract

#### Problem Details — RFC 9457 (obsoletes RFC 7807)

- **What it is.** Defines a standard JSON format for HTTP errors: `type`, `title`, `status`, `detail`, `instance` fields, served as `application/problem+json`. Allows *extension properties*.
- **Where in PayDude.** Every 4xx/5xx response uses `org.springframework.http.ProblemDetail`. The `timestamp` and `errors` extensions are added with `setProperty(...)`. See the per-concern `@RestControllerAdvice` classes and [pattern #15](patterns.md#15-standardised-error-responses-with-rfc-9457-problem-details).
- **Why.** A single error format across the whole API; no client has to parse two different shapes.

#### HTTP semantics — RFC 9110

- **What it is.** The RFC that unifies HTTP semantics (methods, status codes, headers). Replaces the old RFC 7230–7235 series.
- **Where in PayDude.**
  - **§15.5.6** — the `405 Method Not Allowed` handler emits the `Allow` header with the valid verbs.
  - **`429 Too Many Requests`** (introduced by RFC 6585, now part of the status registry) — returned by `RateLimitExceptionHandler` with `Retry-After`.
- **Why.** An automated client can recover (switch verb, retry after `Retry-After`) without parsing the body.

#### Rate-limit signalling — IETF RateLimit header fields (draft-ietf-httpapi-ratelimit-headers)

- **What it is.** A draft IETF standard for advertising a client's remaining quota on *every* response via two HTTP Structured Fields: `RateLimit-Policy` (the static policy — quota `q` per window `w` seconds) and `RateLimit` (the live state — `r` tokens remaining, resets in `t` seconds), correlated by a quoted policy name. It supersedes the de-facto `X-RateLimit-Limit/Remaining/Reset` triple (GitHub, Twitter) and complements `Retry-After`, which only appears on the 429 — i.e. *after* the client is already blocked.
- **Where in PayDude.** `IpRateLimitFilter` emits both fields on every in-scope request to the public token endpoints (`/login`, `/register`, `/refresh`) — on the 2xx as well as the 429 — under a per-endpoint policy name (`"login"`, `"register"`, `"refresh"`). The numbers come from the `RateLimitSnapshot` the bucket returns (`AuthRateLimiter.checkXxxByIp`); `RateLimitHeaders` does the structured-field formatting. Pinned by `RateLimitHeadersTest` and `IpRateLimitFilterTest`.
- **Why.** Proactive signalling lets a well-behaved SDK slow down *before* it trips the limit instead of discovering the wall via a 429 — emitting on the success path is the whole point of the field. The authenticated email/user tiers keep their `Retry-After`-only 429s for now (a mechanical follow-up).

#### OpenAPI 3

- **What it is.** A specification for **describing** REST APIs in a machine-readable document (formerly called Swagger). Not an RFC or ISO; maintained by the OpenAPI Initiative (Linux Foundation).
- **Where in PayDude.** SpringDoc generates the OpenAPI document from the `@Tag`/`@Operation` annotations and serves it in Swagger UI.
- **Why.** The API contract is browsable and a client can be generated automatically.

#### HTTP caching — RFC 9111

- **What it is.** Defines the semantics of the `Cache-Control` header and how proxies and browsers decide what to cache.
- **Where in PayDude.** Spring Security emits `Cache-Control: no-cache, no-store, max-age=0, must-revalidate` on every response; `SecurityConfig` documents that we rely on that default on purpose (account data must not be cached at any intermediate point).
- **Why.** In a financial API, a response carrying an account balance must not survive in a proxy cache or on the browser's disk.

#### CORS — *Fetch Standard* (WHATWG)

- **What it is.** The protocol, defined by the WHATWG *Fetch Standard* (formerly a W3C document), that the browser applies to decide which web origins may call the API from JavaScript.
- **Where in PayDude.** `CorsProperties` (`application.cors.*`) defines the allow-list of origins, methods and headers; `SecurityConfig` applies it via a `CorsConfigurationSource`. `allowCredentials` is `false` on purpose — we authenticate with a Bearer token in the header, not with cookies.
- **Why.** Without CORS configured, no frontend on another origin (the typical case: an SPA on `localhost:3000` against the API on `:8090`) can consume the API.

#### HTTP security headers — OWASP Secure Headers Project

- **What it is.** A set of defensive headers recommended by OWASP: `X-Content-Type-Options`, `Strict-Transport-Security` (HSTS), `Referrer-Policy`, `Content-Security-Policy`, etc.
- **Where in PayDude.** `SecurityConfig` configures the `.headers(...)` block: Spring Security already emits `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `X-XSS-Protection: 0` by default; on top we set HSTS (over HTTPS only), `Referrer-Policy: no-referrer` and `Content-Security-Policy: frame-ancestors 'none'`.
- **Why.** Defense in depth against MIME sniffing, downgrade to HTTP, URL leakage via `Referer`, and clickjacking.

### 2.3 Data and formats

#### Dates — ISO 8601

- **What it is.** The international date/time format: `2026-05-14T21:00:00Z`. Lexicographically sortable, with no time-zone ambiguity.
- **Where in PayDude.** `responseCacheMapper` sets `WRITE_DATES_AS_TIMESTAMPS=false` so `Instant`s always serialize as ISO 8601; the `prod` logs use UTC timestamps.

#### Currency codes — ISO 4217

- **What it is.** The standard for three-letter currency codes: `USD`, `MXN`, `EUR`…
- **Where in PayDude.** The `Currency` enum uses ISO 4217 codes (`USD`, `MXN`); the DB check constrains them. *Today it's implicit* — not cited in the code, but the values are ISO 4217.
- **Why.** Any external financial system understands `USD` without translation.

#### Account numbering — ISO/IEC 7812 + the Luhn algorithm

- **What it is.** ISO/IEC 7812 defines the structure of card/account numbers, including the **Luhn check digit**: a checksum that detects single-digit typos.
- **Where in PayDude.** `AccountNumberGenerator` produces 16 digits: bank prefix + 12 random (`SecureRandom`) + 1 Luhn digit. Incoming transfer account numbers are validated with `@AccountNumber`, so malformed or Luhn-invalid values fail request validation before any account lookup.
- **Why.** A mistyped account number is caught before it ever touches the DB.
- **Masking — last-four display convention (PCI DSS §3.4, applied voluntarily).** PayDude does not process real cards, so PCI DSS is out of scope (see below), but it adopts the standard's last-four masking discipline for account numbers anyway, via `AccountNumberMasker` (`****` + the last four digits). It is applied in two places: every application-log line (full account numbers live only in the audit tables and in the account owner's own response, never in logs), and the **counterparty** account number in transaction responses — the caller is the other side of the transfer, not the counterparty, so a recipient sees only `****1119` of the sender's account rather than the whole identifier. Data minimisation: reveal the least that still lets a human recognise an account.

### 2.4 Observability

#### OpenMetrics (Prometheus exposition format)

- **What it is.** The plain-text format in which metrics are exposed for a scraper (Prometheus, VictoriaMetrics) to read. Standardized under the name OpenMetrics (CNCF).
- **Where in PayDude.** `micrometer-registry-prometheus` serializes every `BusinessMetrics` meter at `/actuator/prometheus` in this format.

#### W3C Trace Context — the `traceparent` header

- **What it is.** The W3C standard for propagating *tracing* context between services: a `traceparent` header carrying a trace-id (128 bits) and a span-id (64 bits) in a fixed format, plus an optional `tracestate` for vendor metadata.
- **Where in PayDude.** The `micrometer-tracing-bridge-otel` dependency puts Spring Boot in charge of the standard: it reads the incoming `traceparent` (or generates a new one) per request and exposes `traceId`/`spanId` in the SLF4J MDC — the Logback pattern reads them in `dev`/`test`, and `LogstashEncoder` flattens them into the JSON in `prod`. It replaces the homegrown `X-Correlation-Id` header the project used before.
- **Why.** A trace-id generated here propagates automatically to any downstream service that speaks the standard, and the day a trace backend (Tempo, Jaeger) is added it integrates with no code change. No exporter is wired today: the bridge is there for propagation + log correlation, not span shipping. `management.tracing.sampling.probability=1.0` — with no exporter the cost is nil and the `traceId` reaches the MDC regardless of sampling.

### 2.5 Supply chain & build security (DevSecOps CI)

The CI pipeline (`.github/workflows/security.yml`, driven by the opt-in `security` Maven profile) adds
the **build-time** security leg, gated to fail on High+Critical with committed suppression files as the
auditable escape hatch.

#### Software Composition Analysis — CVE / NVD / CVSS (MITRE + NIST)

- **What it is.** A **CVE** (Common Vulnerabilities and Exposures, MITRE) is the industry identifier for a known vulnerability; the **NVD** (National Vulnerability Database, NIST) enriches each CVE with a **CVSS** severity score. SCA tools match a project's dependencies against these feeds.
- **Where in PayDude.** **OWASP Dependency-Check** (`dependency-check-maven`) resolves every dependency to its CPE, queries the NVD, and `failBuildOnCVSS=7` fails the build on a High or Critical finding (CVSS ≥ 7). Accepted/false-positive CVEs are documented in `.dependency-check-suppressions.xml`.
- **Why.** Most real-world breaches enter through a known-vulnerable dependency, not first-party code; gating on the NVD turns "keep your dependencies patched" into an enforced contract.

#### Software Bill of Materials — CycloneDX (OWASP / ECMA-424)

- **What it is.** An **SBOM** is a machine-readable inventory of every component in a build. **CycloneDX** is the OWASP SBOM standard, now also **ECMA-424**; SBOMs are increasingly mandated (e.g. US Executive Order 14028).
- **Where in PayDude.** `cyclonedx-maven-plugin` emits `target/bom.json` + `bom.xml` on every CI run, published as a build artifact.
- **Why.** When the next Log4Shell-class CVE lands, an SBOM answers "are we affected, and where" in seconds instead of a code audit.

#### Static Application Security Testing — SpotBugs + FindSecBugs

- **What it is.** SAST analyses the code (here, bytecode) for security bug patterns without running it. **FindSecBugs** adds ~135 security detectors to **SpotBugs**.
- **Where in PayDude.** The `security` profile runs SpotBugs at max effort, scoped to the SECURITY category (`spotbugs-security-include.xml`); each accepted finding is triaged with a written justification in `spotbugs-exclude.xml`, and SARIF is published to the GitHub Security tab.
- **Why.** Catches injection / crypto / deserialization patterns in first-party code that dependency scanning never sees.

#### Container image scanning — Trivy

- **What it is.** Scans a built container image's OS packages and language layers for known CVEs.
- **Where in PayDude.** Trivy scans the runtime image (`eclipse-temurin:21-jre-alpine`) on every CI run, failing on HIGH/CRITICAL (unfixed findings ignored), SARIF to the Security tab.
- **Why.** The base image and its OS packages carry CVEs that neither the Java SCA nor the SAST tools observe — the third, infrastructure leg.

### Industry conventions — *not formal standards*

We follow these because they are widespread good practice, but it's worth knowing they are **not** normative specifications:

| Convention | What it is | Where in PayDude |
|------------|--------|------------------|
| **Idempotency-Key** (Stripe/Square style) | Header to deduplicate write operations; exclude "memo" fields from the fingerprint. | The whole idempotency flow. *There's an IETF draft to formalize it — see §3.2.* |
| **RED method** (Rate, Errors, Duration) | Grafana/Weaveworks methodology for designing dashboards. | The "Golden Signals" dashboard. |
| **URI versioning** (`/v1`) | Convention of Stripe, GitHub, AWS. Not Semantic Versioning, not an RFC. | `@ApiV1` + `WebConfig`. |

---

## 3. Potential standards to raise quality

The following is **not implemented**. It's ordered by topic, and each entry says what it is, what it
would give us, and how much effort it costs — so it reads as a roadmap, not a wish list.

### 3.1 Hardening authentication

> NIST SP 800-63B §5.1.1.2 (length 8–64, no composition rules, breached-password rejection,
> and no forced rotation) is already implemented end-to-end — see §2.1.

#### OWASP ASVS — adopt it as a checklist, not a loose citation

- **What's missing.** Today we cite §2.4.5 (sessions), V2.2 (throttling) and V7 (logging — see §2.1 above). ASVS is a whole document, verifiable by levels (L1/L2/L3); §2.1 (password strength), §2.2 (general rate limiting) and §3 (session management) still apply as a broader audit toward L2.
- **What it would give us.** An objective checklist of "what's left to consider the app secure at L2".
- **Effort.** Low to audit (it's reading and ticking), variable to close the gaps.

#### RFC 7517 — JSON Web Key (JWK) and signing-key rotation

- **What it is.** A standard format for publishing cryptographic keys, and the basis for rotating the JWT signing key without invalidating all live tokens.
- **What it would give us.** Today the HMAC key is single and static (`JWT_SECRET_KEY`). With JWK + a `kid` (key id) in the JWT header, you could rotate the key gradually.
- **Effort.** High — it changes the key model. Probably *over-engineering* for a single-instance service, but worth citing as "the next thing in a real system".

### 3.2 HTTP correctness and robustness

#### IETF draft — `Idempotency-Key` header (draft-ietf-httpapi-idempotency-key-header)

- **What it is.** The IETF is **formalizing** the Idempotency-Key convention we follow Stripe-style today. When it's published as an RFC, there will be a normative spec to align with.
- **What it would give us.** Moving from "we follow Stripe's convention" to "we implement RFC X". Worth tracking the draft.
- **Effort.** Low when it ships — we're already close to the expected behaviour.

> The other low-effort HTTP candidates — **RFC 6750** (Bearer challenge), **RFC 9111** (`Cache-Control`),
> **CORS** and **OWASP Secure Headers** — are already implemented; see §2.1 and §2.2.

### 3.3 Observability

> W3C Trace Context (`traceparent`) is already implemented via `micrometer-tracing-bridge-otel` — see §2.4.
> The next step on this line would be to wire a trace backend (Tempo/Jaeger) to *visualize* the spans,
> not just propagate them and correlate logs — a chunk of infra (another container in the observability
> stack + an OTLP exporter), not an app code change.

### 3.4 Compliance framework

#### PCI DSS — Payment Card Industry Data Security Standard

- **What it is.** The mandatory standard for any system that touches payment-card data.
- **Why it's mentioned.** PayDude is a financial *domain* but does not process real cards, so PCI DSS does not apply today. Worth knowing as the framework that **would** apply to a real bank: encryption at rest, network segmentation, log retention, vulnerability scans. One of its conventions is already borrowed voluntarily — the §3.4 last-four masking of account numbers in logs and cross-party responses (see *Account numbering* above).
- **Effort.** Out of scope here — but worth naming, along with what it would require in a system that does process cards.

---

## 4. Summary table

| Standard | Category | Status in PayDude | Where |
|----------|-----------|-------------------|-------|
| RFC 7519 / 7515 / 2104 (JWT/JWS/HMAC) | Auth | ✅ Used | `JwtService`, `JwtClaimNames` |
| RFC 6749 §5.1 (OAuth token response) | Auth | ✅ Used | `AuthServiceImpl`, `AuthResponse` |
| RFC 9700 (OAuth 2.1 BCP — refresh rotation) | Auth | ✅ Used | `RefreshTokenServiceImpl` |
| RFC 7009 (Token Revocation) | Auth | ✅ Used | `AuthController.logout`, `RefreshTokenServiceImpl.revokeFamily` |
| RFC 6750 §3 (Bearer challenge) | Auth | ✅ Used | `CustomSecurityExceptionHandler`, `JwtAuthenticationFilter` |
| RFC 7617 (HTTP Basic auth) | Auth | ✅ Used | `SecurityConfig.actuatorSecurityFilterChain` (Actuator scrape) |
| RFC 9562 / 4122 (UUID) | Auth/Data | ✅ Used | `Idempotency-Key`, `family_id` |
| RFC 6238 / 4226 (TOTP/HOTP) + NIST 800-63B AAL2 + ASVS V2.8 | Auth | ✅ Used | `TotpService`, `MfaService`, `MfaLoginIT` |
| RFC 9068 / 8725 §3.11 (explicit JWT `typ`) | Auth | ✅ Used | `JwtService` (`at+jwt` / `mfa+jwt`) |
| RFC 4648 §5 (base64url) | Data | ✅ Used | Refresh token, JWT |
| RFC 4648 §6 + §10 (Base32) | Data | ✅ Used | `util/Base32` (TOTP secret, `otpauth://`) |
| RFC 1918 (private IP) | Network security | ✅ Used | `RemoteIpValve`, `IpRateLimitFilter` |
| NIST SP 800-63B §5.1.1.2 | Auth | ✅ Used | `RegisterRequest`, `BreachedPasswordGuard`, `SecurityUser` |
| OWASP ASVS v4 §2.4.5 | Auth | ✅ Used (partial) | `UserServiceImpl.changePassword` |
| OWASP ASVS V2.2 + NIST SP 800-63B §5.2.2 (auth throttling/lockout) | Auth | ✅ Used | `LoginAttemptService`, `AuthRateLimiter` |
| OWASP ASVS V7 (security logging) | Auth | ✅ Used | `SecurityAuditService`, `AdminAuditController` |
| OWASP API4/API6:2023 | API security | ✅ Used | `IpRateLimitFilter`, `AuthRateLimiter`, `WriteRateLimiter`, `ReauthRateLimiter` |
| FIPS 180-4 (SHA-256) | Crypto | ✅ Used | Idempotency, `RefreshTokenServiceImpl` |
| RFC 9457 (Problem Details) | HTTP | ✅ Used | Per-concern advices, `ErrorResponses` |
| RFC 9110 §15.5.6 / 429 | HTTP | ✅ Used | `ValidationExceptionHandler`, `RateLimitExceptionHandler` |
| IETF RateLimit header fields (draft) | HTTP | ✅ Used | `IpRateLimitFilter`, `RateLimitHeaders` |
| RFC 9111 (Cache-Control) | HTTP | ✅ Used | `SecurityConfig` (Spring Security default) |
| CORS (Fetch Standard) | HTTP | ✅ Used | `CorsProperties`, `SecurityConfig` |
| OWASP Secure Headers | HTTP | ✅ Used | `SecurityConfig` (`.headers(...)`) |
| OpenAPI 3 | API | ✅ Used | SpringDoc, `@Tag`/`@Operation` |
| ISO 8601 (dates) | Data | ✅ Used | `responseCacheMapper`, prod logs |
| ISO 4217 (currencies) | Data | ✅ Used (implicit) | `Currency` enum |
| ISO/IEC 7812 + Luhn | Data | ✅ Used | `AccountNumberGenerator` |
| PCI DSS §3.4 last-four masking (convention) | Data protection | ✅ Used | `AccountNumberMasker` (logs + counterparty in responses) |
| OpenMetrics | Observability | ✅ Used | `/actuator/prometheus` |
| Idempotency-Key (Stripe) | Convention | ✅ Used (not an RFC yet) | Idempotency flow |
| RED method | Convention | ✅ Used | Golden Signals dashboard |
| W3C Trace Context (`traceparent`) | Observability | ✅ Used | `micrometer-tracing-bridge-otel`, `logback-spring.xml` |
| CVE / NVD / CVSS (MITRE + NIST) | Supply chain | ✅ Used | OWASP Dependency-Check (CI) |
| CycloneDX SBOM (OWASP / ECMA-424) | Supply chain | ✅ Used | `cyclonedx-maven-plugin` (CI) |
| FindSecBugs (SAST) · Trivy (image) | Supply chain | ✅ Used | `security` Maven profile, `security.yml` |
| OWASP ASVS (full checklist) | Auth | 🔲 Potential | §3.1 |
| RFC 7517 (JWK / key rotation) | Auth | 🔲 Potential | §3.1 |
| IETF Idempotency-Key draft | HTTP | 🔲 Potential | §3.2 |
| PCI DSS | Compliance | 🔲 Out of scope | §3.4 |
