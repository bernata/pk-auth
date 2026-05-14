// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.auth;

import io.dropwizard.auth.AuthFilter;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.Nullable;

/**
 * Bearer-token {@link io.dropwizard.auth.AuthFilter} that extracts a JWT from the {@code
 * Authorization: Bearer ...} header and delegates verification to a {@link PasskeyAuthenticator}.
 * Brief §6.11 — "JWT validation via a Jersey filter".
 *
 * <p>We hand-roll this rather than use Dropwizard's bundled {@code OAuthCredentialAuthFilter}
 * because we want the wire-credential type to be {@link PasskeyCredentials} (strongly typed in the
 * bundle's DI graph) rather than {@code String}.
 */
@Priority(Priorities.AUTHENTICATION)
public final class PasskeyAuthFilter extends AuthFilter<PasskeyCredentials, PasskeyPrincipal> {

  private static final String BEARER_PREFIX = "Bearer ";

  /** Builder honoring the standard {@link AuthFilter.AuthFilterBuilder} contract. */
  public static final class Builder
      extends AuthFilterBuilder<PasskeyCredentials, PasskeyPrincipal, PasskeyAuthFilter> {
    @Override
    protected PasskeyAuthFilter newInstance() {
      return new PasskeyAuthFilter();
    }
  }

  private PasskeyAuthFilter() {}

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    String header = requestContext.getHeaderString("Authorization");
    Optional<PasskeyCredentials> credentials = parseBearer(header);
    boolean authenticated =
        credentials.isPresent() && authenticate(requestContext, credentials.get(), "Bearer");
    if (!authenticated) {
      throw new WebApplicationException(unauthorizedHandler.buildResponse(prefix, realm));
    }
  }

  private static Optional<PasskeyCredentials> parseBearer(@Nullable String header) {
    if (header == null || !header.startsWith(BEARER_PREFIX)) {
      return Optional.empty();
    }
    String token = header.substring(BEARER_PREFIX.length()).trim();
    if (token.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(new PasskeyCredentials(token));
  }

  /** Convenience: produces a fully wired filter from an authenticator. */
  public static PasskeyAuthFilter build(PasskeyAuthenticator authenticator) {
    Objects.requireNonNull(authenticator, "authenticator");
    Builder b = new Builder();
    b.setAuthenticator(authenticator);
    b.setPrefix("Bearer");
    b.setRealm("pk-auth");
    return b.buildAuthFilter();
  }
}
