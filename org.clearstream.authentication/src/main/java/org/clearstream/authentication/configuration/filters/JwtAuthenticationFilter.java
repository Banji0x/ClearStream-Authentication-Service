package org.clearstream.authentication.configuration.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.clearstream.authentication.models.UserSecurityDetails;
import org.clearstream.authentication.models.Users;
import org.clearstream.authentication.models.dto.ErrorResponseDto;
import org.clearstream.authentication.repositories.UserRepository;
import org.clearstream.authentication.services.JwtService;
import org.clearstream.authentication.services.RedisService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  private final JwtService jwtService;
  private final UserRepository userRepository;
  private final RedisService redisService;
  private final ObjectMapper objectMapper;


  public JwtAuthenticationFilter(JwtService jwtService, UserRepository userRepository, RedisService redisService, ObjectMapper objectMapper) {
    this.jwtService = jwtService;
    this.userRepository = userRepository;
    this.redisService = redisService;
    this.objectMapper = objectMapper;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain)
    throws ServletException, IOException {
    // for the auth path's that should be kept open like register and login >
    //probably pass it on to the next filters...
    String path = request.getRequestURI();
    boolean pathMatches = path.startsWith("/api/auth/jwt/");
    if (pathMatches) {
      //if route is the logout route, then it must be authenticated.
      if (path.equals("/api/auth/jwt/user/logout")) {
        //request flow should be allowed to propagate further.
      } else {
        filterChain.doFilter(request, response);
        return;
      }
    }

    //Check Authorization header. If it's not present, then revoke throw authentication exception
    String authorizationHeader = request.getHeader("Authorization");
    if (authorizationHeader == null || authorizationHeader.trim().isEmpty() || !authorizationHeader.startsWith("Bearer ")) {
      unAuthenticatedRequest(response, "Unauthorized", Map.of("access token", "Bad credentials."), HttpStatus.UNAUTHORIZED);
      return;
    }

    //validate token
    String jwtAccessToken = authorizationHeader.substring(7);
    // is it valid ? check jwt expiration date, time and the redis store as well.
    Long userId;
    try {
      jwtService.secureTokenValidityCheck(jwtAccessToken);
      redisService.isJwtAccessTokenBlacklisted(jwtAccessToken);
      userId = jwtService.extractUsername(jwtAccessToken);
    } catch (ExpiredJwtException | org.clearstream.authentication.exceptions.ExpiredJwtException e) {
      unAuthenticatedRequest(response, "Unauthorized", Map.of("access token", "Expired access token."), HttpStatus.UNAUTHORIZED);
      return;
    } catch (JwtException signatureException) {
      unAuthenticatedRequest(response, "Unprocessable entity", Map.of("access token", "Invalid access Token."), HttpStatus.UNPROCESSABLE_ENTITY);
      return;
    }

    //extract user id and verify...
    Optional<Users> userOptional = userRepository.findById(userId);

    if (userOptional.isEmpty()) {
      unAuthenticatedRequest(response, "Bad Credentials", Map.of("access token", "Invalid username or password"), HttpStatus.UNAUTHORIZED);
      return;
    }

    var securityUser = new UserSecurityDetails(userOptional.get());
    securityUser.eraseCredentials();

    //update the Security context holder...
    UsernamePasswordAuthenticationToken authenticatedUser =
      new UsernamePasswordAuthenticationToken(securityUser, null, securityUser.getAuthorities());
    var newContext = SecurityContextHolder.createEmptyContext();
    newContext.setAuthentication(authenticatedUser);
    SecurityContextHolder.setContext(newContext);

    filterChain.doFilter(request, response);
  }

  private void unAuthenticatedRequest(HttpServletResponse response, String exceptionMessage, Map<String, String> errors, HttpStatus httpStatus) {
    response.setStatus(httpStatus.value());
    response.setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE);
    ErrorResponseDto errorResponseDto = new ErrorResponseDto(httpStatus.value(), exceptionMessage, errors, ZonedDateTime.now());
    try {
      String string = objectMapper.writeValueAsString(errorResponseDto);
      response.getWriter().write(string);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
