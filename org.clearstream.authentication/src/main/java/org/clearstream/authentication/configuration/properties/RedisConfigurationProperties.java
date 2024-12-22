package org.clearstream.authentication.configuration.properties;

import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(value = "cache.redis")
@Getter
public class RedisConfigurationProperties {
  private final String accessTokenBlacklistDefaultValue;
  private final String refreshTokenBlacklistDefaultValue;

  public RedisConfigurationProperties(String accessTokenBlacklistDefaultValue, String refreshTokenBlacklistDefaultValue) {
    this.accessTokenBlacklistDefaultValue = accessTokenBlacklistDefaultValue;
    this.refreshTokenBlacklistDefaultValue = refreshTokenBlacklistDefaultValue;
  }
}
