package org.clearstream.authentication.models.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UserLoginRequestDto(
  @Email(regexp = "[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,3}",
    flags = Pattern.Flag.CASE_INSENSITIVE, message = "This Email-address is invalid.")
  @NotBlank(message = "An Email-address is required.")
  String emailAddress,
  @Size(min = 8, max = 20, message = "The Password length must be between 8 to 20 characters.")
  @NotBlank(message = "A Password is required.")
  String password
) {
}
