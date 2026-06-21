package com.jesusf.paydude.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.CONSTRUCTOR;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE_USE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * Validates that a {@code String} is at most {@link #value()} bytes long when encoded as UTF-8.
 *
 * <p>Distinct from {@link jakarta.validation.constraints.Size}, which counts characters (Java
 * {@code char}s), not bytes. A field can satisfy {@code @Size(max = 64)} yet blow a byte budget
 * once non-ASCII characters are involved — 64 two-byte characters are 128 bytes. This constraint
 * guards byte-bounded sinks; in PayDude it caps passwords at BCrypt's 72-byte input limit, beyond
 * which BCrypt silently truncates (so two passphrases sharing a 72-byte prefix would hash to the
 * same value). Rejecting over-budget input with a clear 400 is preferable to silent truncation.
 *
 * <p>{@code null} is considered valid — pair with {@code @NotBlank}/{@code @NotNull} for presence.
 * The same {@link Target} set as {@code @Size} is declared so the constraint propagates correctly
 * onto record components.
 */
@Documented
@Constraint(validatedBy = MaxByteLengthValidator.class)
@Target({ METHOD, FIELD, ANNOTATION_TYPE, CONSTRUCTOR, PARAMETER, TYPE_USE })
@Retention(RUNTIME)
public @interface MaxByteLength {

  String message() default "must be at most {value} bytes when UTF-8 encoded";

  /** Maximum allowed length, in UTF-8 bytes. */
  int value();

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};
}
