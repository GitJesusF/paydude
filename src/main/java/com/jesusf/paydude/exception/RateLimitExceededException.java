package com.jesusf.paydude.exception;

import lombok.Getter;

/**
 * Signals that a caller has exceeded an allowed request rate.
 *
 * <p>Raised from all four throttle tiers — the per-IP infrastructure filter
 * ({@code IpRateLimitFilter}), the per-email auth throttle ({@code AuthController}), the per-user
 * money-moving write throttle ({@code WriteRateLimiter}, via the account/transaction controllers),
 * and the per-user password-re-authentication throttle ({@code ReauthRateLimiter}, via the
 * user/MFA controllers) — and handled by {@code RateLimitExceptionHandler}, which maps it to HTTP
 * 429 Too Many Requests and emits a {@code Retry-After} header built from
 * {@link #getRetryAfterSeconds()}.
 */
@Getter
public class RateLimitExceededException extends RuntimeException {

  /** Seconds the client should wait before retrying; drives the {@code Retry-After} header. */
  private final long retryAfterSeconds;

  /**
   * @param message           human-readable detail for the Problem Details body
   * @param retryAfterSeconds back-off hint surfaced to the client as {@code Retry-After}
   */
  public RateLimitExceededException(String message, long retryAfterSeconds) {
    super(message);
    this.retryAfterSeconds = retryAfterSeconds;
  }
}
