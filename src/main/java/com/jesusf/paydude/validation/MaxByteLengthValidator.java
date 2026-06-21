package com.jesusf.paydude.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.nio.charset.StandardCharsets;

/**
 * Validator for {@link MaxByteLength}: passes when the value's UTF-8 encoding fits the configured
 * byte budget. {@code null} passes — presence is a separate concern (e.g. {@code @NotBlank}).
 */
public class MaxByteLengthValidator implements ConstraintValidator<MaxByteLength, String> {

  private int max;

  @Override
  public void initialize(MaxByteLength constraint) {
    this.max = constraint.value();
  }

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context) {
    if (value == null) {
      return true;
    }
    return value.getBytes(StandardCharsets.UTF_8).length <= max;
  }
}
