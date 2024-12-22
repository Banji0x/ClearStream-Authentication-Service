package org.clearstream.authentication.models.dto;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenDto(@NotBlank(message = "A Refresh-token is required.") String refreshToken) {
}
