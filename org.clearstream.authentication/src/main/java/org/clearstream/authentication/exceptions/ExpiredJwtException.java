package org.clearstream.authentication.exceptions;

import org.springframework.security.core.AuthenticationException;

public class ExpiredJwtException extends AuthenticationException {

  public ExpiredJwtException(String msg) {
    super(msg);
  }
  public ExpiredJwtException() {
    super("Expired access-token.");
  }

}
