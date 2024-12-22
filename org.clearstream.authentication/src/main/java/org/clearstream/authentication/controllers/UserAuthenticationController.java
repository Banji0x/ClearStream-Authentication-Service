package org.clearstream.authentication.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.clearstream.authentication.models.dto.*;
import org.clearstream.authentication.services.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.ZonedDateTime;

@RestController
@RequestMapping("api/auth/jwt/user")
public class UserAuthenticationController {
    private final UserService userService;

    public UserAuthenticationController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<SuccessResponseDto<UserRegistrationSuccessDto>> registerUser(@RequestBody @Valid UserRegistrationRequestDto userRegistrationRequestDto) {
        UserRegistrationSuccessDto userRegistrationSuccessDto = userService.registerUser(userRegistrationRequestDto);
        SuccessResponseDto<UserRegistrationSuccessDto> successResponseDto = new SuccessResponseDto<>(HttpStatus.CREATED.value(), "User registered successfully.", userRegistrationSuccessDto, ZonedDateTime.now());
        return ResponseEntity.status(HttpStatus.CREATED).body(successResponseDto);
    }

    @PostMapping("/login")
    public ResponseEntity<SuccessResponseDto<AccessTokenDto>> loginUser(@RequestBody @Valid UserLoginRequestDto userLoginRequestDto) {
        AccessTokenDto accessTokenDto = userService.loginUser(userLoginRequestDto);
        SuccessResponseDto<AccessTokenDto> successResponseDto = new SuccessResponseDto<>(HttpStatus.OK.value(), "User logged in successfully.", accessTokenDto, ZonedDateTime.now());
        return ResponseEntity.ok().body(successResponseDto);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<SuccessResponseDto<AccessTokenDto>> generateNewAccessAndRefreshToken(@RequestBody @Valid RefreshTokenDto refreshTokenDto, HttpServletRequest httpServletRequest) {
        String refreshToken = refreshTokenDto.refreshToken();
        String authorizationHeader = httpServletRequest.getHeader("Authorization");
        if (authorizationHeader == null || authorizationHeader.trim().isEmpty() || !authorizationHeader.startsWith("Bearer ")) {
            throw new BadCredentialsException("A valid access token is required.");
        }
        String accessToken = authorizationHeader.substring(7);
        AccessTokenDto accessTokenDto = userService.generateNewAccessAndRefreshToken(accessToken, refreshToken);
        SuccessResponseDto<AccessTokenDto> successResponseDto = new SuccessResponseDto<>(HttpStatus.OK.value(), "New refresh token generated.", accessTokenDto, ZonedDateTime.now());
        return ResponseEntity.ok().body(successResponseDto);
    }

    //this route should be a protected route. i.e. the user should be authenticated...
    @PostMapping("/logout")
    public ResponseEntity<SuccessResponseDto<Object>> logoutUser(@RequestBody @Valid LogoutRequestDto logoutRequestDto) {
        userService.logoutUser(logoutRequestDto.accessToken(), logoutRequestDto.refreshToken());
        SuccessResponseDto<Object> successResponseDto = new SuccessResponseDto<>(HttpStatus.OK.value(), "User logged out successfully.", null, ZonedDateTime.now());
        return ResponseEntity.ok().body(successResponseDto);
    }
}