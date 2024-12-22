package org.clearstream.authentication.services;

import org.clearstream.authentication.models.UserRole;
import org.clearstream.authentication.models.UserSecurityDetails;
import org.clearstream.authentication.models.Users;
import org.clearstream.authentication.models.dto.*;
import org.clearstream.authentication.repositories.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
  private final UserRepository userRepository;
  private final PasswordEncoder bcryptPasswordEncoder;
  private final UserDetailsService userDetailsService;
  private final JwtService jwtService;
  private final RedisService redisService;

  public UserService(UserRepository userRepository, PasswordEncoder bcryptPasswordEncoder, UserDetailsService userDetailsService, JwtService jwtService, RedisService redisService) {
    this.userRepository = userRepository;
    this.bcryptPasswordEncoder = bcryptPasswordEncoder;
    this.userDetailsService = userDetailsService;
    this.jwtService = jwtService;
    this.redisService = redisService;
  }

  public UserRegistrationSuccessDto registerUser(UserRegistrationRequestDto userRegistrationRequestDto) {
    //create and save entity
    String encodedPassword = bcryptPasswordEncoder.encode(userRegistrationRequestDto.password());
    String encodedSecretAnswer = bcryptPasswordEncoder.encode(userRegistrationRequestDto.securityAnswer());
    Users users = Users.builder().firstname(userRegistrationRequestDto.firstName()).lastname(userRegistrationRequestDto.lastName()).phoneNumber(userRegistrationRequestDto.phoneNumber()).emailAddress(userRegistrationRequestDto.emailAddress()).password(encodedPassword).homeAddress(userRegistrationRequestDto.homeAddress()).securityQuestion(SecurityQuestion.valueOf(userRegistrationRequestDto.securityQuestion())).userRole(UserRole.CLIENT).securityAnswer(encodedSecretAnswer).enabled(true).build();
    userRepository.save(users);

    //return dto
    return UserRegistrationSuccessDto
      .builder()
      .firstName(users.getFirstname())
      .lastName(users.getLastname())
      .phoneNumber(users.getPhoneNumber())
      .emailAddress(users.getEmailAddress())
      .homeAddress(users.getHomeAddress())
      .securityQuestion(users.getSecurityQuestion())
      .userRole(users.getUserRole())
      .createdAt(users.getCreatedAtTimestamp())
      .status(String.valueOf(HttpStatus.CREATED.value()))
      .message("User Registration Successful.")
      .build();
  }

  public AccessTokenDto loginUser(UserLoginRequestDto userLoginRequestDto) {
    UserSecurityDetails userDetails = (UserSecurityDetails) userDetailsService.loadUserByUsername(userLoginRequestDto.emailAddress());
    boolean matches = bcryptPasswordEncoder.matches(userLoginRequestDto.password(), userDetails.getPassword());
    if (!matches) {
      throw new BadCredentialsException("Incorrect email-address or password.");
    }
    //check if account is disabled
    if (!userDetails.isEnabled()) {
      throw new DisabledException("User account is disabled.");
    }
    //erase credentials
    userDetails.eraseCredentials();
    //generate access token and a refresh token
    String refreshTokenString = jwtService.buildRefreshToken(userDetails, "refresh");
    return jwtService.buildAccessToken(userDetails, "access", refreshTokenString);
  }

  public AccessTokenDto generateNewAccessAndRefreshToken(String currentAccessToken, String refreshToken) {

    //check if refresh token is valid. i.e. check if it hasn't expired and if it's blacklisted in Redis.
    jwtService.secureTokenValidityCheck(refreshToken);
    redisService.isJwtRefreshTokenBlacklisted(refreshToken);

    //extract userid from the refreshToken and accessToken.
    Long refreshTokenUserId = jwtService.extractUsername(refreshToken);
    //since the current access-token can either be expired or still valid, an extraction meant for expired token is going to be used.
    Long accessTokenUserId = jwtService.insecureUsernameExtraction(currentAccessToken);

    //verify if user is a valid one...
    //compare the two user id's.
    if (!refreshTokenUserId.equals(accessTokenUserId)) {
      throw new BadCredentialsException("Invalid access or refresh token.");
    }

    // verify if user exists
    Optional<Users> userOptional = userRepository.findById(refreshTokenUserId);
    Users user = userOptional.orElseThrow(() -> new BadCredentialsException("Invalid Refresh Token."));

    UserSecurityDetails userSecurityDetails = new UserSecurityDetails(user);
    //check if user account is enabled
    boolean userEnabled = userSecurityDetails.isEnabled();
    if (!userEnabled) {
      throw new DisabledException("User Account is Disabled.");
    }
    //erase credentials
    userSecurityDetails.eraseCredentials();

    //add the current refresh-token to blacklist and set the expiration time of the refresh-token to the redis expiration time as well.
    var refreshTokenExpirationTime = jwtService.extractExpiration(refreshToken);
    redisService.blacklistJwtRefreshToken(refreshToken, refreshTokenExpirationTime);

    //generate new access and refresh tokens for the user
    String newRefreshToken = jwtService.buildRefreshToken(userSecurityDetails, "refresh");

    return jwtService.buildAccessToken(userSecurityDetails, "access", newRefreshToken);
  }

  public void logoutUser(String accessToken, String refreshToken) {
    //check token validity
    jwtService.secureTokenValidityCheck(accessToken);
    jwtService.secureTokenValidityCheck(refreshToken);

    //check if token was blacklisted in Redis...
    redisService.isJwtRefreshTokenBlacklisted(refreshToken);
    redisService.isJwtAccessTokenBlacklisted(accessToken);

    //blacklist current tokens and set expiration time in redis.
    var accessTokenExpirationTime = jwtService.extractExpiration(accessToken);
    var refreshTokenExpirationTime = jwtService.extractExpiration(refreshToken);

    redisService.blacklistJwtAccessToken(accessToken, accessTokenExpirationTime);
    redisService.blacklistJwtRefreshToken(refreshToken, refreshTokenExpirationTime);
  }
}
