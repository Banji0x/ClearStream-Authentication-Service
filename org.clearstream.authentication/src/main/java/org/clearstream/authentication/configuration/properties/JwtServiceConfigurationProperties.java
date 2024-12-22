package org.clearstream.authentication.configuration.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(value = "security.jwt")
@Getter
@Validated
public class JwtServiceConfigurationProperties {
  @NotNull
  private final Long accessTokenExpirationTimeInMilliSeconds;
  @NotNull
  private final Long refreshTokenExpirationTimeInMilliSeconds;
  @NotBlank
  private final String secretKey;

  public JwtServiceConfigurationProperties(String secretKey, Long accessTokenExpirationTimeInMilliSeconds, Long refreshTokenExpirationTimeInMilliSeconds) {
    this.secretKey = secretKey;
    this.accessTokenExpirationTimeInMilliSeconds = accessTokenExpirationTimeInMilliSeconds;
    this.refreshTokenExpirationTimeInMilliSeconds = refreshTokenExpirationTimeInMilliSeconds;
  }
}
