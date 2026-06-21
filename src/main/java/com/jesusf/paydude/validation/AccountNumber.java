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
 * Validates PayDude account numbers: exactly 16 decimal digits with a valid Luhn check digit.
 *
 * <p>{@code null} and blank strings are considered valid so callers can pair this with
 * {@code @NotBlank} and keep missing-field errors separate from malformed-account errors.
 */
@Documented
@Constraint(validatedBy = AccountNumberValidator.class)
@Target({ METHOD, FIELD, ANNOTATION_TYPE, CONSTRUCTOR, PARAMETER, TYPE_USE })
@Retention(RUNTIME)
public @interface AccountNumber {

  String message() default "Account number must be a valid 16-digit Luhn number";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};
}
