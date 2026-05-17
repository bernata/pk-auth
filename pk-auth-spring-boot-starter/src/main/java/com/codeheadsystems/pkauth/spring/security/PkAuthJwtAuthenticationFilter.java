// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.security;

import com.codeheadsystems.pkauth.jwt.JwtVerificationResult;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Validates the {@code Authorization: Bearer …} header against {@link PkAuthJwtValidator} and, on
 * success, populates the {@link SecurityContextHolder} with a {@link PkAuthJwtAuthenticationToken}.
 *
 * <p>The filter is intentionally permissive: it does <strong>not</strong> reject a request that has
 * no token or an invalid token. Endpoints that require authentication enforce that via Spring
 * Security's {@code authorizeHttpRequests} chain (configured in the autoconfiguration). Brief §6.10
 * mentions an explicit goal of "JWT validation filter that produces a {@code
 * PkAuthJwtAuthenticationToken}" — that is exactly what we do here, no more.
 *
 * <p><b>Header-only by design.</b> Only the {@code Authorization: Bearer …} header is consulted.
 * Cookies are never read for authentication, which is why the pk-auth filter chain disables CSRF —
 * that posture is correct only as long as no auth path treats a cookie as proof of identity. Do not
 * add a cookie fallback here; host apps that want session-cookie auth should layer their own filter
 * ahead of this one and accept the CSRF responsibilities that come with it.
 *
 * <p><b>Design note.</b> This filter intentionally bypasses Spring's {@code AuthenticationManager}
 * for zero-overhead JWT validation. There is no companion {@code AuthenticationProvider} — host
 * apps that need the canonical manager pipeline can declare their own filter + provider.
 */
public final class PkAuthJwtAuthenticationFilter extends OncePerRequestFilter {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthJwtAuthenticationFilter.class);
  private static final String BEARER_PREFIX = "Bearer ";

  private final PkAuthJwtValidator validator;

  public PkAuthJwtAuthenticationFilter(PkAuthJwtValidator validator) {
    this.validator = validator;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String header = request.getHeader("Authorization");
    if (header == null || !header.startsWith(BEARER_PREFIX)) {
      chain.doFilter(request, response);
      return;
    }
    String token = header.substring(BEARER_PREFIX.length()).trim();
    if (token.isEmpty()) {
      chain.doFilter(request, response);
      return;
    }
    JwtVerificationResult result = validator.validate(token);
    if (result instanceof JwtVerificationResult.Success success) {
      PkAuthJwtAuthenticationToken auth =
          new PkAuthJwtAuthenticationToken(success.claims().userHandle(), success.claims(), token);
      SecurityContextHolder.getContext().setAuthentication(auth);
      LOG.debug(
          "jwt.authenticate user={} method={}",
          success.claims().userHandle(),
          success.claims().method());
    } else {
      LOG.debug("jwt.authenticate reject result={}", result.getClass().getSimpleName());
    }
    chain.doFilter(request, response);
  }
}
