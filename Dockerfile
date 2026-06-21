# syntax=docker/dockerfile:1.7
#
# Multi-stage build. The build stage downloads dependencies and packages the
# fat jar; the runtime stage runs only the layered output on a slim JRE.

FROM maven:3.9.16-eclipse-temurin-21-alpine AS build
WORKDIR /app

# Layer 1: dependency resolution. Cached as long as pom.xml + lombok.config
# don't change, which is the expensive part of a cold build.
COPY pom.xml lombok.config ./
RUN mvn -B dependency:go-offline

# Layer 2: source compile + package. Tests are skipped here because CI runs
# them in a separate `./mvnw verify` step (the image is built only when that
# step is green). Skipping tests inside the image build keeps the build
# reproducible — flaky tests do not block the image build, but they do block
# the upstream CI gate.
COPY src ./src
RUN mvn -B package -DskipTests

# Layered-jar extraction. Spring Boot 3.2+ ships `jarmode=tools` which splits
# a fat jar into four layers ordered by churn frequency. The slowest-changing
# layer (third-party deps) is cached across rebuilds, so an app-code-only
# change ships a tiny final layer instead of a fresh ~50 MB blob.
RUN java -Djarmode=tools -jar target/*.jar extract --layers --destination extracted

# ----------------------------------------------------------------------------
# Runtime image — JRE only (no JDK or Maven), Alpine for size, non-root user
# with a fixed UID/GID for predictable volume permissions in any host context.
# ----------------------------------------------------------------------------
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Patch the base image's Alpine OS packages. The published eclipse-temurin:21-jre-alpine
# tag lags behind Alpine security updates, so the Trivy gate flags fixable HIGH CVEs in
# OS packages (e.g. openssl/libcrypto3, CVE-2026-45447) until they are upgraded here.
RUN apk --no-cache upgrade

# Fixed UID/GID make volume mounts and any future SELinux / AppArmor profiles
# reproducible. UID 10001 sits in the "system services" range (>10000) that
# most host policies reserve for unprivileged service accounts.
RUN addgroup -S -g 10001 spring && adduser -S -u 10001 -G spring spring

# Copy in layer order: slowest-changing first, fastest-changing last. Docker's
# build cache invalidates on the first layer that changed, so application/
# (which changes every commit) sits at the bottom and dependencies/ (which
# changes only on pom.xml edits) sits at the top and stays cached.
COPY --from=build --chown=spring:spring /app/extracted/dependencies/ ./
COPY --from=build --chown=spring:spring /app/extracted/spring-boot-loader/ ./
COPY --from=build --chown=spring:spring /app/extracted/snapshot-dependencies/ ./
COPY --from=build --chown=spring:spring /app/extracted/application/ ./

USER spring:spring

EXPOSE 8090

# In-image HEALTHCHECK so `docker run` (without compose) still wires the
# readiness probe to the container's reported health. Compose's healthcheck
# block overrides this one when running under compose; both point at the same
# endpoint, so behavior is identical either way. wget ships with BusyBox in
# eclipse-temurin:21-jre-alpine — exit code alone is the signal, no shell
# pipe / grep needed.
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=5 \
  CMD wget -q -O /dev/null http://localhost:8090/actuator/health/readiness || exit 1

# JarLauncher entry point (Spring Boot 3.2+ moved it to the .launch subpackage).
# Runs the layered jar from the directory layout extracted above — no fat jar
# at runtime, so the Docker layer cache is the unit of immutability instead of
# a single 50 MB artifact.
ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]