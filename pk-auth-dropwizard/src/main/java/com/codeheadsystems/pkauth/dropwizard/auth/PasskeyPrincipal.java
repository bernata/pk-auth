// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.auth;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import java.security.Principal;
import java.util.Objects;

/**
 * The Dropwizard {@link Principal} surfaced after a successful JWT verification. Carries the
 * pk-auth {@link UserHandle} so resources can scope work to the authenticated user.
 */
public final class PasskeyPrincipal implements Principal {

  private final UserHandle userHandle;
  private final String jti;

  /**
   * Constructs a new principal.
   *
   * @param userHandle the authenticated user's handle (JWT {@code sub}).
   * @param jti the unique token id (JWT {@code jti}).
   */
  public PasskeyPrincipal(UserHandle userHandle, String jti) {
    this.userHandle = Objects.requireNonNull(userHandle, "userHandle");
    this.jti = Objects.requireNonNull(jti, "jti");
  }

  @Override
  public String getName() {
    return Base64Url.encode(userHandle.value());
  }

  /** The authenticated user's pk-auth {@link UserHandle}. */
  public UserHandle userHandle() {
    return userHandle;
  }

  /** The unique JWT id (often useful for audit logs / revocation). */
  public String jti() {
    return jti;
  }
}
