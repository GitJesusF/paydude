package com.jesusf.paydude.enums;

/**
 * The result of an audited security event. Stored as a string and pinned by a CHECK constraint in
 * {@code V0_003}.
 *
 * <p>Kept as a separate dimension from {@link SecurityAuditEventType} so an operator can filter
 * "every failure" across event kinds — the same split as the {@code outcome} tag on the
 * {@code paydude.auth.login} metric.
 */
public enum SecurityAuditOutcome {
  SUCCESS,
  FAILURE
}
