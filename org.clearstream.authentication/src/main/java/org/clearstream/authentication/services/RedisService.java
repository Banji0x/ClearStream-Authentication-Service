package org.clearstream.authentication.services;

import org.clearstream.authentication.configuration.properties.RedisConfigurationProperties;
import org.clearstream.authentication.exceptions.ExpiredJwtException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
public class RedisService {
  private final RedisTemplate<String, String> redisTemplate;
  private final RedisConfigurationProperties redisConfigurationProperties;

  public RedisService(RedisTemplate<String, String> redisTemplate, RedisConfigurationProperties redisConfigurationProperties) {
    this.redisTemplate = redisTemplate;
    this.redisConfigurationProperties = redisConfigurationProperties;
  }

  public void blacklistJwtAccessToken(String accessToken, Date accessTokenExpirationTime) {
    long expirationInMilliseconds = accessTokenExpirationTime.getTime() - System.currentTimeMillis();
    long expirationInSeconds = TimeUnit.MILLISECONDS.toSeconds(expirationInMilliseconds);
    redisTemplate.opsForValue().set(accessToken, redisConfigurationProperties.getAccessTokenBlacklistDefaultValue(), expirationInSeconds, TimeUnit.SECONDS);
  }

  public void isJwtAccessTokenBlacklisted(String accessToken) {
    tokenBlacklistCheck(accessToken);
  }

  public void isJwtRefreshTokenBlacklisted(String refreshToken) {
    tokenBlacklistCheck(refreshToken);
  }

  private void tokenBlacklistCheck(String token) {
    Boolean hasKey = redisTemplate.hasKey(token);
    if (Boolean.TRUE.equals(hasKey)) {
      throw new ExpiredJwtException();
    }
  }

  public void blacklistJwtRefreshToken(String refreshToken, Date refreshTokenExpirationTime) {
    long expirationInMilliseconds = refreshTokenExpirationTime.getTime() - System.currentTimeMillis();
    long expirationInSeconds = TimeUnit.MILLISECONDS.toSeconds(expirationInMilliseconds);
    redisTemplate.opsForValue().set(refreshToken, redisConfigurationProperties.getRefreshTokenBlacklistDefaultValue(), expirationInSeconds, TimeUnit.SECONDS);
  }
}
