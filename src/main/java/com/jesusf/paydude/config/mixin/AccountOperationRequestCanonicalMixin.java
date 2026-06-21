package com.jesusf.paydude.config.mixin;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * Canonical-hash mix-in for account balance operations.
 *
 * <p>{@code description} is intentionally excluded from the idempotency fingerprint because it is
 * memo text, not part of the financial identity of the operation. A retry that only changes a
 * client-side note should replay the original result instead of creating a false conflict.
 */
public interface AccountOperationRequestCanonicalMixin {

  @JsonIgnore
  String description();
}
