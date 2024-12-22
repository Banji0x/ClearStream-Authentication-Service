package org.clearstream.authentication.annotations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import org.clearstream.authentication.configuration.validator.SecurityQuestionValidator;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD})
@Constraint(validatedBy = SecurityQuestionValidator.class)
public @interface ValidSecurityQuestion {
  String message() default "Invalid security question";
  Class<?>[] groups() default {};
  Class<? extends Payload>[] payload() default {};
}
