package org.clearstream.authentication.models.dto;

import jakarta.validation.constraints.NotBlank;

public record LogoutRequestDto(@NotBlank(message = "An access-token is required.") String accessToken,
                               @NotBlank(message = "A refresh-token is required.") String refreshToken) {

}
