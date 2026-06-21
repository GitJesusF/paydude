package com.jesusf.paydude.metrics;

import com.jesusf.paydude.metrics.BusinessMetrics.IdempotencyConflictReason;
import com.jesusf.paydude.metrics.BusinessMetrics.TransferFailureReason;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link BusinessMetrics}.
 *
 * <p>The component is a thin facade over Micrometer, so the value of these tests is not in
 * exercising arithmetic but in pinning the externally observable contract: metric names, tag
 * keys, tag values, and the fact that the Timer actually records on {@code stop}. Anything that
 * a Grafana panel or alert rule could depend on lives in this file.
 *
 * <p>{@link SimpleMeterRegistry} is the real Micrometer in-memory registry — no mocks. If a
 * future change accidentally renames {@code paydude.transfer.completed} or swaps the
 * {@code reason} tag for {@code cause}, the test fails on a name lookup, not on a brittle
 * Mockito verify. The {@code SimpleMeterRegistry} is created fresh per test to avoid leakage
 * between cases.
 */
class BusinessMetricsTest {

  private MeterRegistry registry;
  private BusinessMetrics metrics;

  @BeforeEach
  void setUp() {
    registry = new SimpleMeterRegistry();
    metrics = new BusinessMetrics(registry);
  }

  @Nested
  @DisplayName("Transfer flow — counters and timer")
  class TransferFlow {

    @Test
    @DisplayName("recordTransferCompleted increments paydude.transfer.completed")
    void shouldIncrementTransferCompleted() {
      metrics.recordTransferCompleted();
      metrics.recordTransferCompleted();

      Counter counter = registry.find("paydude.transfer.completed").counter();
      assertNotNull(counter, "Counter paydude.transfer.completed should be registered");
      assertEquals(2.0, counter.count(), "Counter should reflect both increments");
    }

    @Test
    @DisplayName("recordTransferFailed creates separate series per reason tag")
    void shouldTagFailuresByReason() {
      // The reason tag is the only thing separating the rejection causes; renaming it (say, to
      // "cause") would silently break every existing dashboard and alert.
      metrics.recordTransferFailed(TransferFailureReason.INSUFFICIENT_FUNDS);
      metrics.recordTransferFailed(TransferFailureReason.INSUFFICIENT_FUNDS);
      metrics.recordTransferFailed(TransferFailureReason.OWNERSHIP_VIOLATION);

      Counter insufficient = registry.find("paydude.transfer.failed")
          .tag("reason", "INSUFFICIENT_FUNDS")
          .counter();
      Counter ownership = registry.find("paydude.transfer.failed")
          .tag("reason", "OWNERSHIP_VIOLATION")
          .counter();

      assertNotNull(insufficient, "Series with reason=INSUFFICIENT_FUNDS must exist");
      assertNotNull(ownership, "Series with reason=OWNERSHIP_VIOLATION must exist");
      assertEquals(2.0, insufficient.count());
      assertEquals(1.0, ownership.count());
    }

    @Test
    @DisplayName("Timer sample records a non-zero duration on stop")
    void shouldRecordTransferDuration() {
      // Not measuring wall-clock (flaky); only that the start/stop dance ends up emitting to
      // the meter — a forgotten stop in production would flatline the p99 and this would catch it.
      Timer.Sample sample = metrics.startTransferTimer();
      // Small deterministic busy-wait so the Timer accumulates a duration > 0.
      long deadline = System.nanoTime() + Duration.ofMillis(1).toNanos();
      while (System.nanoTime() < deadline) {
        // spin
      }
      metrics.stopTransferTimer(sample);

      Timer timer = registry.find("paydude.transfer.duration").timer();
      assertNotNull(timer, "Timer paydude.transfer.duration should be registered");
      assertEquals(1L, timer.count(), "Exactly one transfer attempt was measured");
      assertTrue(timer.totalTime(java.util.concurrent.TimeUnit.NANOSECONDS) > 0,
          "Total recorded duration must be strictly positive");
    }
  }

  @Nested
  @DisplayName("Idempotency flow — replay and conflict counters")
  class IdempotencyFlow {

    @Test
    @DisplayName("recordIdempotencyReplay increments paydude.idempotency.replay")
    void shouldIncrementReplay() {
      metrics.recordIdempotencyReplay();

      Counter replay = registry.find("paydude.idempotency.replay").counter();
      assertNotNull(replay);
      assertEquals(1.0, replay.count());
    }

    @Test
    @DisplayName("recordIdempotencyConflict tags each conflict reason as a separate series")
    void shouldTagConflictByReason() {
      metrics.recordIdempotencyConflict(IdempotencyConflictReason.HASH_MISMATCH);
      metrics.recordIdempotencyConflict(IdempotencyConflictReason.STILL_PENDING);
      metrics.recordIdempotencyConflict(IdempotencyConflictReason.STILL_PENDING);

      Counter hashMismatch = registry.find("paydude.idempotency.conflict")
          .tag("reason", "HASH_MISMATCH")
          .counter();
      Counter stillPending = registry.find("paydude.idempotency.conflict")
          .tag("reason", "STILL_PENDING")
          .counter();

      assertNotNull(hashMismatch);
      assertNotNull(stillPending);
      assertEquals(1.0, hashMismatch.count());
      assertEquals(2.0, stillPending.count());
    }
  }

  @Nested
  @DisplayName("Auth flow — login outcome tag and register counter")
  class AuthFlow {

    @Test
    @DisplayName("recordLogin tags outcome=success or failure")
    void shouldTagLoginOutcome() {
      // The outcome tag is the canonical credential-stuffing signal (failure growing without
      // matching success); changing its values would silently unhook the alert.
      metrics.recordLogin(true);
      metrics.recordLogin(true);
      metrics.recordLogin(false);

      Counter success = registry.find("paydude.auth.login")
          .tag("outcome", "success")
          .counter();
      Counter failure = registry.find("paydude.auth.login")
          .tag("outcome", "failure")
          .counter();

      assertEquals(2.0, success.count());
      assertEquals(1.0, failure.count());
    }

    @Test
    @DisplayName("recordRegister increments paydude.auth.register")
    void shouldIncrementRegister() {
      metrics.recordRegister();

      Counter register = registry.find("paydude.auth.register").counter();
      assertNotNull(register);
      assertEquals(1.0, register.count());
    }

    @Test
    @DisplayName("recordAccountLocked increments paydude.auth.lockout")
    void shouldIncrementAccountLocked() {
      // A sustained rise here means an attacker is tripping the failure threshold across many
      // accounts — the alert matches this exact name.
      metrics.recordAccountLocked();
      metrics.recordAccountLocked();

      Counter lockout = registry.find("paydude.auth.lockout").counter();
      assertNotNull(lockout, "Counter paydude.auth.lockout should be registered");
      assertEquals(2.0, lockout.count());
    }

    @Test
    @DisplayName("recordMfaVerification tags outcome=success or failure on paydude.auth.mfa")
    void shouldTagMfaVerificationOutcome() {
      // Every attempt here already passed the password, so rising failures are strictly more
      // alarming than on paydude.auth.login: compromised passwords hitting the second factor.
      // Same tag vocabulary as login so queries compose.
      metrics.recordMfaVerification(true);
      metrics.recordMfaVerification(false);
      metrics.recordMfaVerification(false);

      Counter success = registry.find("paydude.auth.mfa")
          .tag("outcome", "success")
          .counter();
      Counter failure = registry.find("paydude.auth.mfa")
          .tag("outcome", "failure")
          .counter();

      assertEquals(1.0, success.count());
      assertEquals(2.0, failure.count());
    }
  }

  @Nested
  @DisplayName("Pre-registered meters are discoverable at /actuator/metrics on cold start")
  class PreRegistration {

    @Test
    @DisplayName("Pre-registered counters and timer exist with zero value before first increment")
    void shouldPreRegisterMetricsAtConstruction() {
      // Nothing is incremented — construction alone must expose the names so a cold-start
      // dashboard renders a flat zero line instead of a misleading "no data". Tagged counters
      // (failed, conflict, login) are deliberately absent: their series materialize lazily
      // per tag combination.
      assertNotNull(registry.find("paydude.transfer.completed").counter());
      assertNotNull(registry.find("paydude.transfer.duration").timer());
      assertNotNull(registry.find("paydude.idempotency.replay").counter());
      assertNotNull(registry.find("paydude.auth.register").counter());
      assertNotNull(registry.find("paydude.auth.lockout").counter());

      long preRegisteredCount = registry.getMeters().stream()
          .map(Meter::getId)
          .filter(id -> id.getName().startsWith("paydude."))
          .count();
      assertTrue(preRegisteredCount >= 5,
          "At least the five pre-registered paydude.* meters should be discoverable");
    }
  }
}
