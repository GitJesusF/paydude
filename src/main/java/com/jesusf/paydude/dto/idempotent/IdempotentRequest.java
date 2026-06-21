package com.jesusf.paydude.dto.idempotent;

/**
 * Marker for request DTOs that are eligible to be deduplicated through the idempotency-key
 * machinery. The interface itself carries no behavior — its only job is to give
 * {@code IdempotencyKeyService.reserveKey} a compile-time contract: callers cannot pass an
 * arbitrary object, only a DTO that has been explicitly opted in.
 *
 * <p>It is {@code sealed} so the universe of idempotent operations is documented in a single
 * place. Adding a new operation requires extending the {@code permits} clause, which makes the
 * design intent visible at code-review time and prevents ad-hoc DTOs from silently joining the
 * contract.
 *
 * <p>This interface and every permitted DTO live together in {@code dto/idempotent/} because
 * sealed permits must share a package in the unnamed module (JLS §8.1.1.2), and because
 * idempotency is a transversal capability — orthogonal to the {@code account}/{@code transactions}
 * subdomain split that the rest of {@code dto/} follows.
 *
 * <p>Hashing assumes Jackson can serialize implementations without custom configuration beyond
 * what {@code canonicalJsonMapper} already provides — i.e. plain Java records / POJOs.
 */
public sealed interface IdempotentRequest permits AccountOperationRequest, TransferRequest {
}