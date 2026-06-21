package com.jesusf.paydude.exception;

/**
 * Signals the violation of a domain rule — insufficient funds, a currency
 * mismatch, an idempotency-key conflict, a breached password, and similar.
 *
 * <p>Handled by {@code BusinessExceptionHandler} and mapped to HTTP 409
 * Conflict. It is unchecked so it can propagate out of a {@code @Transactional}
 * method and trigger a rollback without polluting service signatures.
 */
public class BusinessException extends RuntimeException {

  /**
   * @param message human-readable detail; surfaced verbatim in the
   *                {@code detail} field of the Problem Details response
   */
  public BusinessException(String message) {
    super(message);
  }
}
