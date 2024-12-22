package org.clearstream.authentication.configuration.validator;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.clearstream.authentication.annotations.ValidSecurityQuestion;
import org.clearstream.authentication.models.dto.SecurityQuestion;

public class SecurityQuestionValidator implements ConstraintValidator<ValidSecurityQuestion, String> {


  @Override
  public boolean isValid(String value, ConstraintValidatorContext context) {
    if (value == null || value.isEmpty()) {
      return false;
    }
    for (SecurityQuestion securityQuestion : SecurityQuestion.values()) {
      if (securityQuestion.name().equalsIgnoreCase(value)) {
        return true;
      }
    }
    return false;
  }
}
