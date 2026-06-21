package com.jesusf.paydude.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

/**
 * Single entry point for emitting custom business metrics.
 *
 * <p>Encapsulating every {@link MeterRegistry} interaction here keeps the service layer free of
 * Micrometer boilerplate (no {@code Counter.builder(...)} or stray tag strings scattered across
 * the codebase), centralises the metric vocabulary, and gives test code one place to substitute
 * a {@code SimpleMeterRegistry} for assertions.
 *
 * <p>The metric surface is intentionally small — nine observable series — and oriented toward
 * what an operator actually needs on a Grafana panel during an incident, not toward
 * instrumenting every method "just in case":
 *
 * <ul>
 *   <li>{@code paydude.transfer.completed} (Counter): successful transfers. Pre-registered so
 *       its description is visible in {@code /actuator/metrics}.</li>
 *   <li>{@code paydude.transfer.failed} (Counter, tag {@code reason}): rejected transfers,
 *       broken down by the domain reason. The tag values come from a small fixed vocabulary —
 *       see {@link TransferFailureReason}.</li>
 *   <li>{@code paydude.transfer.duration} (Timer): wall-clock time of a transfer attempt
 *       (success or failure). Pin the SLO panels on its p95/p99.</li>
 *   <li>{@code paydude.idempotency.replay} (Counter): cache-hit replays — directly proportional
 *       to the work the idempotency layer saved.</li>
 *   <li>{@code paydude.idempotency.conflict} (Counter, tag {@code reason}): same key reused with
 *       different request body / status mismatch — a sustained increase signals a buggy client
 *       or an attack.</li>
 *   <li>{@code paydude.auth.login} (Counter, tag {@code outcome}): {@code success} or
 *       {@code failure}. A spike of failures is the canonical credential-stuffing signal.</li>
 *   <li>{@code paydude.auth.register} (Counter): completed registrations. Used to size capacity
 *       and to baseline what a "normal" registration rate looks like.</li>
 *   <li>{@code paydude.auth.lockout} (Counter): accounts locked after consecutive failed logins.
 *       A sustained rise is a credential-stuffing signal. Pre-registered so it shows at zero.</li>
 *   <li>{@code paydude.auth.mfa} (Counter, tag {@code outcome}): TOTP/recovery-code verifications
 *       at the login step-up. Failures here already passed the password stage — a spike means
 *       compromised passwords being stopped by the second factor.</li>
 * </ul>
 *
 * <p>Where Counter values are pre-registered (no tags) the field is constructed in the
 * constructor with {@link Counter#builder} and a description; where the metric varies by tag,
 * the lookup is deferred to {@code MeterRegistry.counter(name, tagKey, tagValue)} per call
 * (Micrometer internally caches the resolved meter so the per-call cost is a hash-map lookup).
 */
@Component
public class BusinessMetrics {

  private final MeterRegistry meterRegistry;

  private final Counter transferCompleted;
  private final Timer transferDuration;
  private final Counter idempotencyReplay;
  private final Counter authRegister;
  private final Counter authAccountLocked;

  public BusinessMetrics(MeterRegistry meterRegistry) {
    this.meterRegistry = meterRegistry;
    this.transferCompleted = Counter.builder("paydude.transfer.completed")
        .description("Number of transfers that completed successfully")
        .register(meterRegistry);
    this.transferDuration = Timer.builder("paydude.transfer.duration")
        .description("Wall-clock duration of a transfer attempt (success or failure)")
        // Histogram buckets are opt-in: a bare Timer exports only _count/_sum/_max, and the
        // Grafana latency panel computes p50/p95/p99 with histogram_quantile(), which needs the
        // _bucket series. Without this line that panel can never have data.
        .publishPercentileHistogram()
        .register(meterRegistry);
    this.idempotencyReplay = Counter.builder("paydude.idempotency.replay")
        .description("Idempotency replays served from cache (the work the layer saved)")
        .register(meterRegistry);
    this.authRegister = Counter.builder("paydude.auth.register")
        .description("Completed user registrations")
        .register(meterRegistry);
    this.authAccountLocked = Counter.builder("paydude.auth.lockout")
        .description("Accounts locked after consecutive failed login attempts (anti-bruteforce)")
        .register(meterRegistry);
  }

  /**
   * Domain reasons a transfer can be rejected. Exposed as an enum so the call-site cannot
   * accidentally emit a free-form string ({@code "insufficient"} vs {@code "Insufficient funds"})
   * that would cardinality-explode the metric in the time-series database.
   */
  public enum TransferFailureReason {
    INSUFFICIENT_FUNDS,
    OWNERSHIP_VIOLATION,
    CURRENCY_MISMATCH,
    ACCOUNT_INACTIVE
  }

  /**
   * Conflict reasons captured when an idempotency key is reused with a mismatch. Used as the
   * {@code reason} tag on {@code paydude.idempotency.conflict}.
   */
  public enum IdempotencyConflictReason {
    HASH_MISMATCH,
    PREVIOUS_FAILED,
    STILL_PENDING
  }

  // ---------------------------------------------------------------------------------------------
  // Transfer flow.
  // ---------------------------------------------------------------------------------------------

  /** Records one successful transfer ({@code paydude.transfer.completed}). */
  public void recordTransferCompleted() {
    transferCompleted.increment();
  }

  /**
   * Records one rejected transfer ({@code paydude.transfer.failed}), tagged with the cause.
   *
   * @param reason the domain reason the transfer was rejected
   */
  public void recordTransferFailed(TransferFailureReason reason) {
    meterRegistry.counter("paydude.transfer.failed", "reason", reason.name()).increment();
  }

  /**
   * Starts a wall-clock measurement for a transfer attempt. The returned sample MUST be stopped
   * via {@link #stopTransferTimer(Timer.Sample)} regardless of outcome (use a {@code finally}
   * block at the call-site) so latency distributions stay accurate even on the failure path.
   */
  public Timer.Sample startTransferTimer() {
    return Timer.start(meterRegistry);
  }

  /**
   * Stops a sample opened by {@link #startTransferTimer()} and records the elapsed time into
   * {@code paydude.transfer.duration}.
   *
   * @param sample the sample returned by {@link #startTransferTimer()}
   */
  public void stopTransferTimer(Timer.Sample sample) {
    sample.stop(transferDuration);
  }

  // ---------------------------------------------------------------------------------------------
  // Idempotency flow.
  // ---------------------------------------------------------------------------------------------

  /** Records one cache-hit replay ({@code paydude.idempotency.replay}) — work the layer saved. */
  public void recordIdempotencyReplay() {
    idempotencyReplay.increment();
  }

  /**
   * Records one idempotency-key conflict ({@code paydude.idempotency.conflict}), tagged with the
   * cause.
   *
   * @param reason why the reused key was rejected
   */
  public void recordIdempotencyConflict(IdempotencyConflictReason reason) {
    meterRegistry.counter("paydude.idempotency.conflict", "reason", reason.name()).increment();
  }

  // ---------------------------------------------------------------------------------------------
  // Auth flow.
  // ---------------------------------------------------------------------------------------------

  /**
   * Records one login attempt ({@code paydude.auth.login}), tagged by outcome.
   *
   * @param success {@code true} for a successful login, {@code false} for a failed one
   */
  public void recordLogin(boolean success) {
    meterRegistry.counter("paydude.auth.login", "outcome", success ? "success" : "failure")
        .increment();
  }

  /** Records one completed user registration ({@code paydude.auth.register}). */
  public void recordRegister() {
    authRegister.increment();
  }

  /**
   * Records one account locked by the anti-bruteforce policy ({@code paydude.auth.lockout}). A
   * sustained increase is a credential-stuffing signal: an attacker is tripping the consecutive
   * failed-login threshold across many accounts.
   */
  public void recordAccountLocked() {
    authAccountLocked.increment();
  }

  /**
   * Records one MFA verification attempt ({@code paydude.auth.mfa}), tagged by outcome. A spike
   * of failures means someone holds correct passwords and is guessing codes — strictly more
   * alarming than the login-failure counter, because every attempt here already passed the
   * password stage.
   *
   * @param success {@code true} when the code verified and tokens were issued
   */
  public void recordMfaVerification(boolean success) {
    meterRegistry.counter("paydude.auth.mfa", "outcome", success ? "success" : "failure")
        .increment();
  }
}