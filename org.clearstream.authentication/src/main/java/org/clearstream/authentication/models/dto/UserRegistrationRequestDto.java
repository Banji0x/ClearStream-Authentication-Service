package org.clearstream.authentication.models.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.clearstream.authentication.annotations.ValidSecurityQuestion;

public record UserRegistrationRequestDto(
  @NotBlank(message = "A valid First-name is required.") @Size(min = 3, max = 20, message = "First-name must be between 3 to 20 characters.") String firstName,
  @NotBlank(message = "A valid Last-name is required.") @Size(min = 3, max = 20, message = "Last-name must be between 3 to 20 characters.") String lastName,
  @NotBlank(message = "A valid Phone number is required.") @Pattern(regexp = "^\\+?([0-9]{1,4})[-. ]?([0-9]{3,4})[-. ]?([0-9]{3,4})[-. ]?([0-9]{3,4})$", message = "Invalid phone number.")
  String phoneNumber,
  @Email(regexp = "[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,3}",
    flags = Pattern.Flag.CASE_INSENSITIVE, message = "Invalid Email-address.")
  @NotBlank(message = "A valid Email-address is required.")
  String emailAddress,
  @Size(min = 8, max = 20, message = "The Password length must be between 8 to 20 characters.")
  @NotBlank(message = "A valid Password is required.")
  String password,
  @Pattern(
    regexp = "^[\\p{L}0-9 ,.'/#-]{5,100}$",
    message = "Home address must be between 5 and 100 characters."
  )
  @NotBlank(message = "A valid Home address is required.")
  String homeAddress,
  @ValidSecurityQuestion(message = "Invalid Security question selection.")
  String securityQuestion,
  @Pattern(
    regexp = "^(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9 ?!.,'-]{10,100}$",
    message = "Security answer must be between 10 and 100 characters, contain at least one letter and one number."
  )
  @NotBlank(message = "A Security answer is required.")
  String securityAnswer) {
}