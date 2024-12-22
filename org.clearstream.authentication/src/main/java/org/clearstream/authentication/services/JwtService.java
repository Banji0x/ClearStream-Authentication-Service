package org.clearstream.authentication.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.clearstream.authentication.configuration.properties.JwtServiceConfigurationProperties;
import org.clearstream.authentication.models.dto.AccessTokenDto;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.function.Function;

@Service
@Getter
public class JwtService {
  private final SecretKey jwtSecretKey;
  private final Long refreshTokenExpirationTime;
  private final Long accessTokenExpirationTime;


  public JwtService(JwtServiceConfigurationProperties jwtServiceConfigurationProperties) {
    this.refreshTokenExpirationTime = jwtServiceConfigurationProperties.getRefreshTokenExpirationTimeInMilliSeconds();
    this.accessTokenExpirationTime = jwtServiceConfigurationProperties.getAccessTokenExpirationTimeInMilliSeconds();
    this.jwtSecretKey = Keys.hmacShaKeyFor(jwtServiceConfigurationProperties.getSecretKey().getBytes());
  }


  private String buildToken(UserDetails userDetails, String claim, long expirationTime) {
    return Jwts.builder().subject(userDetails.getUsername()).issuedAt(Date.from(Instant.now())).expiration(Date.from(Instant.now().plusMillis(expirationTime))).signWith(signingKey()).claim("type", claim).compact();
  }

  public AccessTokenDto buildAccessToken(UserDetails userDetails, String claim, String refreshToken) {
    return AccessTokenDto.builder().accessToken(buildToken(userDetails, claim, accessTokenExpirationTime)).refreshToken(refreshToken).build();
  }

  public String buildRefreshToken(UserDetails userDetails, String claim) {
    return buildToken(userDetails, claim, refreshTokenExpirationTime);
  }

  public void secureTokenValidityCheck(String token) {
    extractExpiration(token);
  }

  public Long extractUsername(String token) {
    return Long.valueOf(extractClaim(token, (Claims::getSubject)));
  }

  public Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  private <R> R extractClaim(String token, Function<Claims, R> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  private Claims extractAllClaims(String token) {
    return Jwts
      .parser()
      .verifyWith(signingKey())
      .build()
      .parseSignedClaims(token)
      .getPayload();
  }

  private SecretKey signingKey() {
    return jwtSecretKey;
  }

  public Long insecureUsernameExtraction(String currentAccessToken) {
    return Long.valueOf(Jwts.parser()
      .verifyWith(signingKey())
      .clockSkewSeconds(Integer.MAX_VALUE) // Bypass expiration check
      .build()
      .parseSignedClaims(currentAccessToken)
      .getPayload()
      .getSubject());
  }
}
