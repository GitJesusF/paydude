package com.jesusf.paydude.config.mixin;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.jesusf.paydude.config.IdempotencyConfig;

/**
 * Jackson mix-in that customizes how {@code TransferRequest} is serialized by
 * {@code canonicalJsonMapper} for idempotency hashing — without forcing the DTO itself to carry
 * infrastructure-specific annotations.
 *
 * <p>The mix-in is registered exclusively on {@code canonicalJsonMapper} (see
 * {@link IdempotencyConfig}); the application's primary {@code ObjectMapper} used for HTTP
 * responses is unaffected, so {@code description} keeps appearing in API payloads as expected.
 *
 * <p><b>What this mix-in does:</b> excludes {@code description} from the canonical JSON used to
 * compute {@code request_hash}.
 *
 * <p><b>Why:</b> {@code description} is user-facing free text — a memo line, not part of the
 * operation's financial identity. Two retries with the same {@code (sourceAccount, targetAccount,
 * amount, currency)} but different descriptions describe the <i>same</i> transfer, and the
 * idempotency layer should treat them as such. This matches the convention used by major
 * payment processors (Stripe, Square): metadata-style fields are excluded from idempotency
 * fingerprinting so a UI that auto-trims or auto-formats the memo on retry doesn't trigger a
 * spurious "different request" rejection.
 *
 * <p><b>Behavior change vs the previous implementation:</b> historically the in-line
 * {@code calculateHash} included {@code description} in the digest. After this mix-in, two calls
 * to {@code reserveKey} with the same key and identical financial fields but different
 * descriptions will resolve to the same hash — the second call will return the cached response
 * from the first. Callers that relied on description differences to defeat idempotency must use
 * a different idempotency key.
 *
 * <p><b>Why an interface (mix-in) instead of annotating the DTO directly:</b> {@code TransferRequest}
 * is a domain DTO; pinning {@code @JsonIgnore} on its {@code description} field would mean
 * "ignore this everywhere", which is wrong — HTTP responses still need the description. A mix-in
 * scopes the annotation to a single {@code ObjectMapper} instance, keeping the DTO clean and the
 * canonicalization rules co-located with the canonicalization mapper.
 */
public interface TransferRequestCanonicalMixin {

  @JsonIgnore
  String description();
}