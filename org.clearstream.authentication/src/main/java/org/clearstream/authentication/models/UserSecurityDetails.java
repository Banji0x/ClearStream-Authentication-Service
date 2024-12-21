package org.clearstream.authentication.models;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class UserSecurityDetails extends Users implements UserDetails, CredentialsContainer {
  private final Users users;

  public UserSecurityDetails(Users users) {
    this.users = users;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of(() -> "ROLE_" + users.getUserRole().toString());
  }

  @Override
  public String getPassword() {
    return users.getPassword();
  }

  @Override
  public String getUsername() {
    return users.getUserId().toString();
  }

  @Override
  public boolean isAccountNonExpired() {
    return isEnabled();
  }

  @Override
  public boolean isAccountNonLocked() {
    return isEnabled();
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return isEnabled();
  }

  @Override
  public boolean isEnabled() {
    return users.getEnabled();
  }


  @Override
  public void eraseCredentials() {
    users.setPassword(null);
    users.setSecurityQuestion(null);
    users.setSecurityAnswer(null);
  }
}