# Deployment & production hardening

PayDude ships four Docker Compose layouts covering the lifecycle from inner dev loop to a
production-hardened deploy — see [README → Running with Docker](../README.md#running-with-docker)
for the full table and when to use each.

This page documents what the **production overlay** (`docker-compose.prod.yml`) adds on top of the
base file. It lives here, rather than in the README, so the README stays skimmable while the
operational detail remains one click away.

## What the production overlay enforces

`docker-compose.prod.yml` is a compose overlay (same idiom as the observability stack) that hardens the base file along seven axes. Each one mirrors something you would otherwise have to remember when authoring a Kubernetes manifest or an ECS task definition:

| Concern | Override | Why it matters |
|---------|----------|----------------|
| **Mandatory secrets** | `${JWT_SECRET_KEY:?...}`, `${DB_PASSWORD:?...}`, `${CORS_ALLOWED_ORIGINS:?...}` | The base file keeps convenience defaults so a fresh clone runs. The overlay flips them to fail-fast — `docker compose up` exits immediately with the message if any is unset, so no deployment can ever ship with the convenience JWT key from the base file. |
| **DB not published** | `db.ports: []` | Clears the host port mapping declared in the base file. The DB becomes reachable only from inside the Compose network — the posture of a managed Postgres behind a private subnet. |
| **Resource limits** | `mem_limit`, `cpus`, `pids_limit` on both services | A runaway container cannot starve the host or its sibling. The app also gets `JAVA_TOOL_OPTIONS` with `-XX:MaxRAMPercentage=75.0` so the JVM heap respects the cgroup instead of OOM-killing the container. |
| **Restart + signal handling** | `restart: unless-stopped`, `init: true` | Transient crashes auto-recover; `init: true` installs a tini-style PID 1 so `SIGTERM` reaches the JVM and the graceful-shutdown chain (`server.shutdown=graceful`, `spring.lifecycle.timeout-per-shutdown-phase=30s`) actually runs during rolling deploys. |
| **Log rotation** | `logging: { driver: json-file, options: { max-size, max-file } }` | Without these, a leaky logger fills the host disk over weeks. The JSON driver pairs with the `LogstashEncoder` output so the logs land structured. |
| **Least privilege** | `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, non-root user (UID 10001 baked into the Dockerfile) | Spring Boot needs zero Linux capabilities; dropping them all blocks an exploited dependency from reaching for `CAP_NET_RAW`, `CAP_SYS_PTRACE`, etc. `no-new-privileges` blocks setuid escalation from any future base-image change. |
| **Immutable rootfs** | `read_only: true`, `tmpfs: /tmp` (64 MB) | Only `/tmp` (Tomcat work dir, heap dumps, JIT temp) is writable. A compromised dependency cannot persist a payload across restarts. |

The image itself is a multi-stage, layered-JAR build (dependencies cached in a layer separate from application code) running as a fixed-UID non-root user with an in-image `HEALTHCHECK` on `/actuator/health/readiness`. The overlay deliberately stops at the compose boundary — TLS termination, external secret managers, and multi-replica orchestration belong to the layer above it (a reverse proxy or cloud LB, Vault / SOPS / Secrets Manager, and Kubernetes / ECS respectively).
