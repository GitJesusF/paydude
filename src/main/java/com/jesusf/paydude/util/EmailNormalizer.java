package com.jesusf.paydude.util;

import java.util.Locale;

/**
 * Canonical form for email identity.
 *
 * <p>The application treats email as a login identifier, not as display text. Trimming and
 * lower-casing with {@link Locale#ROOT} prevents {@code Maria@example.com} and
 * {@code maria@example.com} from becoming different accounts or different rate-limit buckets.
 */
public final class EmailNormalizer {

  private EmailNormalizer() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }

  public static String normalize(String email) {
    return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
  }
}
