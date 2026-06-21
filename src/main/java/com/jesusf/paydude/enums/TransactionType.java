package com.jesusf.paydude.enums;

/**
 * The direction of a transaction relative to the requesting user.
 *
 * <p>This type is not stored on the transaction row — a single transfer is
 * {@link #SENT} for one party and {@link #RECEIVED} for the other. The
 * {@code TransactionResponseAssembler} derives it per request from the caller's
 * point of view.
 */
public enum TransactionType {

  /** The authenticated user is the source account of the transaction. */
  SENT,

  /** The authenticated user is the target account of the transaction. */
  RECEIVED
}