package com.jesusf.paydude.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class EmailNormalizerTest {

  @Test
  @DisplayName("Canonicalizes email identity by trimming and lower-casing")
  void shouldCanonicalizeEmailIdentity() {
    assertEquals("maria@example.com", EmailNormalizer.normalize("  Maria@Example.COM  "));
  }

  @Test
  @DisplayName("Preserves null so Jakarta validation can report missing input")
  void shouldPreserveNull() {
    assertNull(EmailNormalizer.normalize(null));
  }
}
