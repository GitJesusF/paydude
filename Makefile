# PayDude — common developer tasks. The single front door for running this project.
#
# `make` (or `make help`) lists every target with a one-line description. That help text is
# generated from the `## ` comments on each target below, so it can never drift from the targets
# themselves — add a target with a `## ` comment and it shows up automatically.
#
# Targets are deliberately thin: the only place with real orchestration (Docker daemon / port /
# healthcheck probing) is scripts/dev.sh, which `make dev` simply calls. Make is the menu; the
# script is the logic.

.DEFAULT_GOAL := help

# Observability is a Compose OVERLAY of the base stack, so it always needs BOTH files. Holding the
# command in one variable keeps `obs` and `down` from ever disagreeing on the file list.
OBS := docker compose -f docker-compose.yml -f docker-compose.observability.yml

.PHONY: dev up obs down test verify security help

dev: ## Code on the app — JVM + Dockerized Postgres (dev profile, Swagger at :8090)
	scripts/dev.sh

up: ## Run the whole stack in Docker (prod profile — JSON logs, no Swagger)
	docker compose up -d

obs: ## Full stack + Grafana/Loki/Prometheus dashboards (Grafana at :3000)
	$(OBS) up -d
	@echo "Grafana    -> http://localhost:3000  (anonymous Admin, no login)"
	@echo "Prometheus -> http://localhost:9090"

down: ## Stop everything (the Docker stack and the dev-loop Postgres)
	-$(OBS) down
	-scripts/dev.sh --down

test: ## Fast unit tests — Surefire, no Docker
	./mvnw test

verify: ## Unit + integration tests with the merged JaCoCo report (needs Docker)
	./mvnw verify

security: ## DevSecOps scans — SCA + SAST + SBOM via the opt-in profile (slow, NVD feed)
	./mvnw -Psecurity verify -DskipTests

help: ## Show this help
	@grep -E '^[a-z]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
