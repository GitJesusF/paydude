package com.jesusf.paydude.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

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
 * Validates an {@code Idempotency-Key} request header: present (non-blank) and shaped as a
 * canonical UUID — 8-4-4-4-12 hex, RFC 4122 textual form.
 *
 * <p>A <b>composed constraint</b> (Jakarta Validation 3.0 §2.3): it carries no validator of its own
 * ({@code @Constraint(validatedBy = {})}) and instead bundles {@link NotBlank} and {@link Pattern}.
 * The money-moving write endpoints (deposit, withdraw, transfer) each take the key as a
 * {@code @RequestHeader} parameter, so the rule lived inline on three parameters across two
 * controllers; folding it into one annotation removes that repetition and gives the constraint a
 * single home next to the project's other custom constraints ({@code @AccountNumber}).
 *
 * <p>{@code @ReportAsSingleViolation} is deliberately <b>not</b> used: the two composing constraints
 * keep their own messages, so a blank header still reports "must not be blank" and a malformed one
 * "must be a valid UUID" — identical to the previous inline annotations.
 */
@Documented
@NotBlank(message = "Idempotency-Key header must not be blank")
@Pattern(
    regexp = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    message = "Idempotency-Key must be a valid UUID")
@Constraint(validatedBy = {})
@Target({ METHOD, FIELD, ANNOTATION_TYPE, CONSTRUCTOR, PARAMETER, TYPE_USE })
@Retention(RUNTIME)
public @interface IdempotencyKey {

  String message() default "Idempotency-Key must be a non-blank UUID";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};
}
