// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.auth;

import java.util.Objects;

/**
 * Credentials passed into {@link PasskeyAuthenticator}. For the JWT-bearer flow this is just the
 * raw token string; declared as a wrapper type so the Dropwizard {@code Authenticator} contract is
 * strongly typed.
 *
 * @param token the bearer JWT extracted from the {@code Authorization} header.
 */
public record PasskeyCredentials(String token) {
  public PasskeyCredentials {
    Objects.requireNonNull(token, "token");
  }
}
