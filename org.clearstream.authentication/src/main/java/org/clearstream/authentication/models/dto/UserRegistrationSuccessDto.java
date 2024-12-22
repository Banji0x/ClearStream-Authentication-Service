package org.clearstream.authentication.models.dto;

import lombok.Builder;
import org.clearstream.authentication.models.UserRole;

import java.util.Date;

@Builder
public record UserRegistrationSuccessDto(String status, String message, String firstName, String lastName,
                                         String phoneNumber, String emailAddress,
                                         String homeAddress, SecurityQuestion securityQuestion,
                                         UserRole userRole,
                                         Date createdAt) {
}
