// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.security;

import com.codeheadsystems.pkauth.jwt.JwtVerificationResult;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Spring Security {@link AuthenticationProvider} that converts a {@link PreAuthenticatedJwtToken}
 * (the unauthenticated form produced by the filter when configured for explicit
 * AuthenticationManager use) into a fully-authenticated {@link JwtAuthenticationToken}.
 *
 * <p>The starter's default wiring uses the simpler {@link PkAuthJwtAuthenticationFilter} which sets
 * the authentication directly on {@code SecurityContextHolder}. This provider exists for host apps
 * that prefer the canonical AuthenticationManager pipeline (e.g. when they want their own {@code
 * AuthenticationFailureHandler}). Brief §6.10 calls for both shapes.
 */
public final class PkAuthAuthenticationProvider implements AuthenticationProvider {

  private final PkAuthJwtValidator validator;

  public PkAuthAuthenticationProvider(PkAuthJwtValidator validator) {
    this.validator = validator;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (!(authentication instanceof PreAuthenticatedJwtToken pre)) {
      return null;
    }
    JwtVerificationResult result = validator.validate(pre.getToken());
    if (result instanceof JwtVerificationResult.Success success) {
      return new JwtAuthenticationToken(
          success.claims().userHandle(), success.claims(), pre.getToken());
    }
    throw new BadCredentialsException("Invalid pk-auth JWT: " + result.getClass().getSimpleName());
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return PreAuthenticatedJwtToken.class.isAssignableFrom(authentication);
  }
}
