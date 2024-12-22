package org.clearstream.authentication.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.clearstream.authentication.configuration.filters.JwtAuthenticationFilter;
import org.clearstream.authentication.models.dto.ErrorResponseDto;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import java.io.IOException;
import java.time.ZonedDateTime;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ObjectMapper objectMapper;

    public SecurityConfiguration(ObjectMapper objectMapper, JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.objectMapper = objectMapper;
    }

    @Bean
    @Order
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return
                http
                        .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
                            authorizationManagerRequestMatcherRegistry
                                    .requestMatchers("/api/auth/jwt/user/logout")
                                    .authenticated()
                                    .requestMatchers("/api/auth/**", "/error/**")
                                    .permitAll()
                                    .requestMatchers("/actuator/**").hasRole("ADMIN")
                                    .anyRequest()
                                    .authenticated();
                        })
                        .exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
                            httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(authenticationEntryPoint());
                            httpSecurityExceptionHandlingConfigurer.accessDeniedHandler(accessDeniedHandler());
                        })
                        .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(STATELESS))
                        .csrf(AbstractHttpConfigurer::disable)
                        .addFilterBefore(jwtAuthenticationFilter, AuthorizationFilter.class)
                        .build();
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authenticationException) -> {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE);
            ErrorResponseDto errorResponseDto = new ErrorResponseDto(HttpStatus.UNAUTHORIZED.value(), "Bad Credentials.", null, ZonedDateTime.now());
            try {
                String string = objectMapper.writeValueAsString(errorResponseDto);
                response.getWriter().write(string);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        };
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE);
            ErrorResponseDto errorResponseDto = new ErrorResponseDto(HttpStatus.FORBIDDEN.value(), "Access is Denied.", null, ZonedDateTime.now());
            try {
                String string = objectMapper.writeValueAsString(errorResponseDto);
                response.getWriter().write(string);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        };
    }


}
