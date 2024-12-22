package org.clearstream.authentication.models.dto;

import lombok.Builder;

@Builder
public record AccessTokenDto(String accessToken, String refreshToken) {
}
