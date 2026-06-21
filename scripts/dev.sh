#!/usr/bin/env bash
#
# dev.sh — inner-loop dev environment launcher for PayDude.
#
# Brings up Postgres in a container (docker-compose.db-only.yml), waits until its
# healthcheck reports `healthy`, then runs the app on your local JVM with the `dev`
# profile. The app stays in the foreground; Ctrl-C stops it but leaves Postgres up
# so the next start is instant. Run `scripts/dev.sh --down` to stop Postgres.
#
# Why a script: the most common "container won't start / unhealthy" failures are
# (1) the Docker daemon is down, (2) port 5432 is already taken by a local Postgres,
# (3) a stale `paydude-db` volume is corrupted. A bare `docker compose up` hides all
# three behind a generic error. This script checks each up front and, if the DB never
# turns healthy, dumps the container logs instead of leaving you guessing.
#
set -euo pipefail

# --- location: the script runs from the repo root regardless of where it is invoked ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

COMPOSE_FILE="docker-compose.db-only.yml"
DB_CONTAINER="paydude-db"
DB_PORT=5432
HEALTH_TIMEOUT=90   # max seconds to wait for the container healthcheck

# --- colors (disabled when stdout is not a terminal, e.g. in CI) ---
if [[ -t 1 ]]; then
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BOLD=''; RESET=''
fi
info()  { echo "${BOLD}==>${RESET} $*"; }
ok()    { echo "${GREEN}✓${RESET} $*"; }
warn()  { echo "${YELLOW}!${RESET} $*"; }
die()   { echo "${RED}✗ $*${RESET}" >&2; exit 1; }

# --- usage / help ---
usage() {
  cat <<EOF
${BOLD}dev.sh${RESET} — inner-loop dev launcher for PayDude.

Brings up Postgres (docker-compose.db-only.yml), waits until it is healthy, then
runs the app on your local JVM with the 'dev' profile (foreground; Ctrl-C stops the
app but leaves Postgres up for an instant next start).

${BOLD}Usage:${RESET}
  scripts/dev.sh             Start Postgres (if needed) and run the app.
  scripts/dev.sh --down      Stop Postgres (data persists; 'down -v' wipes it).
  scripts/dev.sh -h|--help   Show this help.
EOF
}

# --- argument parsing: resolve --help and reject unknown flags up front, before the Docker
# checks below, so `dev.sh --help` works even where Docker/Compose is not installed. ---
case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  ''|--down) ;;                 # valid; --down is actioned below (it needs Docker Compose)
  *)         usage >&2; die "Unknown argument: '$1'." ;;
esac

# --- docker compose v2 (`docker compose`) with a fallback to the legacy v1 binary ---
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  die "Docker Compose is not installed. Install Docker Desktop or the compose-v2 plugin."
fi

# --- subcommand --down: shut Postgres down and exit ---
if [[ "${1:-}" == "--down" ]]; then
  info "Stopping Postgres..."
  "${COMPOSE[@]}" -f "${COMPOSE_FILE}" down
  ok "Postgres stopped. (Data persists in the volume; use 'down -v' to wipe it.)"
  exit 0
fi

# --- 1. the Docker daemon must be alive ---
info "Checking the Docker daemon..."
if ! docker info >/dev/null 2>&1; then
  die "The Docker daemon is not responding.
    - Linux:   sudo systemctl start docker
    - Desktop: open Docker Desktop and wait until the icon says 'running'
    If you see 'permission denied', add yourself to the docker group:
      sudo usermod -aG docker \$USER   (requires re-login)"
fi
ok "Docker daemon is up."

# --- 2. is port 5432 already taken by something other than our container? ---
# A local Postgres listening on 5432 makes the container fail to bind the port, and
# compose reports it as a generic error. We detect it before attempting the `up`.
port_owner_is_ours() {
  # Is the container holding 5432 paydude-db? Then there is no conflict.
  docker ps --filter "publish=${DB_PORT}" --format '{{.Names}}' 2>/dev/null | grep -qx "${DB_CONTAINER}"
}
if command -v ss >/dev/null 2>&1 && ss -ltn "( sport = :${DB_PORT} )" 2>/dev/null | grep -q ":${DB_PORT}"; then
  if ! port_owner_is_ours; then
    die "Port ${DB_PORT} is already in use by another process (a local Postgres?).
    Inspect who holds it:   sudo ss -ltnp '( sport = :${DB_PORT} )'
    Then stop that service, e.g.:  sudo systemctl stop postgresql"
  fi
fi

# --- 3. bring Postgres up ---
info "Bringing Postgres up (${COMPOSE_FILE})..."
if ! "${COMPOSE[@]}" -f "${COMPOSE_FILE}" up -d; then
  die "compose up failed. Check the output above."
fi

# --- 4. wait for the container healthcheck to turn 'healthy' ---
# The compose file defines the healthcheck with pg_isready; here we poll it with a timeout.
# If it never turns healthy, we dump the logs instead of leaving the user in the dark.
info "Waiting for Postgres to become healthy (timeout ${HEALTH_TIMEOUT}s)..."
elapsed=0
while true; do
  status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${DB_CONTAINER}" 2>/dev/null || echo "missing")"
  case "${status}" in
    healthy)
      ok "Postgres is healthy."
      break
      ;;
    missing)
      die "Container ${DB_CONTAINER} does not exist — compose did not create it. Check the 'compose up' output."
      ;;
    *)
      if (( elapsed >= HEALTH_TIMEOUT )); then
        echo
        warn "Postgres did not reach 'healthy' within ${HEALTH_TIMEOUT}s (last status: ${status})."
        echo "${BOLD}--- last 40 log lines from the container ---${RESET}"
        docker logs --tail 40 "${DB_CONTAINER}" 2>&1 || true
        echo "${BOLD}--------------------------------------------${RESET}"
        die "Typical causes:
    - Corrupted data volume from a previous run. Start from scratch:
        ${COMPOSE[*]} -f ${COMPOSE_FILE} down -v && scripts/dev.sh
    - Not enough resources (RAM/disk) for the container."
      fi
      printf '.'
      sleep 3
      elapsed=$(( elapsed + 3 ))
      ;;
  esac
done

# --- 5. start the app on the local JVM with the dev profile ---
# spring-boot-docker-compose is NOT triggered here: the DB is already up and we pass the
# dev profile explicitly. The app stays in the foreground; Ctrl-C stops it and leaves
# Postgres running for the next start.
echo
info "Starting the app (dev profile) on :8090 — Swagger at http://localhost:8090/swagger-ui/index.html"
info "Ctrl-C to stop the app. To stop Postgres afterwards:  scripts/dev.sh --down"
echo
exec ./mvnw spring-boot:run -Dspring-boot.run.profiles=dev