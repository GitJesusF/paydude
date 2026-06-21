package com.jesusf.paydude.exception;

/**
 * Signals that a requested entity — a user, account or transaction — does not
 * exist or is not visible to the caller.
 *
 * <p>Handled by {@code BusinessExceptionHandler} and mapped to HTTP 404 Not
 * Found.
 */
public class ResourceNotFoundException extends RuntimeException {

  /**
   * @param message human-readable detail; surfaced verbatim in the
   *                {@code detail} field of the Problem Details response
   */
  public ResourceNotFoundException(String message) {
    super(message);
  }
}
