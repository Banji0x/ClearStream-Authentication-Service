package org.clearstream.authentication.models.dto;

import lombok.Getter;

@Getter
public enum SecurityQuestion {

  FIRST_PET("What is the name of your first pet?"),
  FIRST_CAR("What was the first car you owned?"),
  STREET_NAME("What is the name of the street where you grew up?"),
  MOTHERS_MAIDEN_NAME("What is your mother’s maiden name?"),
  FIRST_SCHOOL("What was the name of your first school?");

  private final String question;

  SecurityQuestion(String question) {
    this.question = question;
  }

}
