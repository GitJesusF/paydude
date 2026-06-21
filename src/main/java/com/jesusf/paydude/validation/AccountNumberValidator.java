package com.jesusf.paydude.validation;

import com.jesusf.paydude.util.Luhn;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

/** Validator for {@link AccountNumber}. */
public class AccountNumberValidator implements ConstraintValidator<AccountNumber, String> {

  private static final int ACCOUNT_NUMBER_LENGTH = 16;

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context) {
    if (value == null || value.isBlank()) {
      return true;
    }
    if (value.length() != ACCOUNT_NUMBER_LENGTH || !value.chars().allMatch(Character::isDigit)) {
      return false;
    }
    return Luhn.isValid(value);
  }
}
