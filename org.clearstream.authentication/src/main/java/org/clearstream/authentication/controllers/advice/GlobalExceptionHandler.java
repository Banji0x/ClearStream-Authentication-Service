package org.clearstream.authentication.controllers.advice;

import com.fasterxml.jackson.databind.JsonMappingException;
import io.jsonwebtoken.JwtException;
import org.clearstream.authentication.exceptions.ExpiredJwtException;
import org.clearstream.authentication.models.dto.ErrorResponseDto;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;


@ControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ErrorResponseDto> methodArgumentNotValidException(MethodArgumentNotValidException methodArgumentNotValidException) {
    Map<String, String> collectedErrors = methodArgumentNotValidException
      .getBindingResult()
      .getFieldErrors()
      .stream()
      .collect(Collectors.toMap(FieldError::getField, FieldError::getDefaultMessage, (existingFieldError, newFieldError) -> existingFieldError));

    ErrorResponseDto errorResponseDto = new ErrorResponseDto(HttpStatus.BAD_REQUEST.value(), "Validation Failed.", collectedErrors, ZonedDateTime.now());
    return ResponseEntity.badRequest().body(errorResponseDto);
  }

  @ExceptionHandler(ExpiredJwtException.class)
  public ResponseEntity<ErrorResponseDto> expiredJwtException(ExpiredJwtException expiredJwtException) {
    ErrorResponseDto errorResponseDto = new ErrorResponseDto(HttpStatus.UNAUTHORIZED.value(), "Bad Credentials.", Map.of("access token", expiredJwtException.getMessage()), ZonedDateTime.now());
    return ResponseEntity.status(401).body(errorResponseDto);
  }
  @ExceptionHandler(AuthenticationException.class)
  public ResponseEntity<ErrorResponseDto> usernameNotFoundException(AuthenticationException authenticationException) {
    ErrorResponseDto errorResponseDto = new ErrorResponseDto(HttpStatus.UNAUTHORIZED.value(), "Bad Credentials.", Map.of("Invalid key", authenticationException.getMessage()), ZonedDateTime.now());
    return ResponseEntity.status(401).body(errorResponseDto);
  }

  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<ErrorResponseDto> usernameNotFoundException(AccessDeniedException accessDeniedException) {
    ErrorResponseDto errorResponseDto = new ErrorResponseDto(HttpStatus.FORBIDDEN.value(), "Forbidden.", Map.of("Invalid key", accessDeniedException.getMessage()), ZonedDateTime.now());
    return ResponseEntity.status(401).body(errorResponseDto);
  }

  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<ErrorResponseDto> httpMessageNotReadableException(HttpMessageNotReadableException httpMessageNotReadableException) {
    String exceptionMessage = "Request body is not readable. Missing or invalid fields.";
    String errorField = "Request body";

    Throwable cause = httpMessageNotReadableException.getMostSpecificCause();
    if (cause instanceof JsonMappingException jsonMappingException) {
      errorField = jsonMappingException.getPath().stream()
        .map(JsonMappingException.Reference::getFieldName)
        .collect(Collectors.joining("."));
      exceptionMessage = "Request body is not readable. Missing or invalid field.";
    }
    ErrorResponseDto errorResponseDto = new ErrorResponseDto(HttpStatus.UNPROCESSABLE_ENTITY.value(), exceptionMessage, Map.of(errorField, "Missing or invalid fields."), ZonedDateTime.now());
    return ResponseEntity.unprocessableEntity().body(errorResponseDto);
  }

  @ExceptionHandler(DataIntegrityViolationException.class)
  public ResponseEntity<ErrorResponseDto> dataIntegrityViolationException(DataIntegrityViolationException dataIntegrityViolationException) {
    ConstraintViolationException dataIntegrityViolationExceptionCause = (ConstraintViolationException) dataIntegrityViolationException.getCause();
    String constraint = Objects.requireNonNull(dataIntegrityViolationExceptionCause.getConstraintName()).substring(6);
    ErrorResponseDto errorResponseDto = new ErrorResponseDto(HttpStatus.UNPROCESSABLE_ENTITY.value(), "Unprocessable entity.", Map.of(constraint, constraint + " already exists."), ZonedDateTime.now());
    return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(errorResponseDto);
  }

  @ExceptionHandler(JwtException.class)
  public ResponseEntity<ErrorResponseDto> handleJwtException(JwtException ignored) {
    ErrorResponseDto error = new ErrorResponseDto(
      HttpStatus.UNPROCESSABLE_ENTITY.value(),
      HttpStatus.UNPROCESSABLE_ENTITY.getReasonPhrase(), Map.of("refresh-token", "Invalid access or refresh token."), ZonedDateTime.now());
    return new ResponseEntity<>(error, HttpStatus.UNPROCESSABLE_ENTITY);
  }

  @ExceptionHandler(NoResourceFoundException.class)
  public ResponseEntity<ErrorResponseDto> noResourceFoundException(NoResourceFoundException ignored) {
    ErrorResponseDto error = new ErrorResponseDto(
      HttpStatus.BAD_REQUEST.value(),
      "Path doesn't exist.", null, ZonedDateTime.now());
    return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorResponseDto> handleGeneralException(Exception ignored) {
    ErrorResponseDto error = new ErrorResponseDto(
      HttpStatus.INTERNAL_SERVER_ERROR.value(),
      "Internal Server Error", null, ZonedDateTime.now());
    return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
  }
}
