// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.security;

import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * Marker {@code Authentication} used by host apps that want to defer JWT validation to the
 * canonical Spring {@code AuthenticationManager} pipeline rather than letting the filter set the
 * {@code SecurityContextHolder} directly. {@link PkAuthAuthenticationProvider} consumes this and
 * upgrades it to a fully-authenticated {@link JwtAuthenticationToken}.
 */
public final class PreAuthenticatedJwtToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = 1L;

  private final String token;

  public PreAuthenticatedJwtToken(String token) {
    super(List.of());
    this.token = token;
    setAuthenticated(false);
  }

  @Override
  public Object getCredentials() {
    return token;
  }

  @Override
  public Object getPrincipal() {
    return token;
  }

  public String getToken() {
    return token;
  }
}
