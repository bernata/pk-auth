// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.util.Objects;
import java.util.Optional;

/**
 * Host-app integration point that maps usernames to pk-auth user handles. pk-auth does not own the
 * users table; the host application is the source of truth.
 */
public interface UserLookup {

  Optional<UserHandle> findUserHandleByUsername(String username);

  Optional<UserView> findUserByHandle(UserHandle handle);

  /** Returns an existing user handle for {@code username} or creates and returns a new one. */
  UserHandle createOrGetUserHandle(String username);

  /**
   * Returns the email address bound to {@code handle} if the host has one — used by {@link
   * com.codeheadsystems.pkauth.spi /*magiclink*} flows to guarantee that the email the caller
   * supplies for an email-verification magic-link actually belongs to the target user (instead of
   * trusting a caller-supplied address that an attacker could substitute).
   *
   * <p>Default returns {@link Optional#empty()}; in that case {@code MagicLinkService} logs a
   * warning and proceeds with the caller-supplied email — the host is responsible for binding
   * elsewhere. Hosts that store an email on the user record should override this to return it so
   * magic-link verification can reject mismatched addresses.
   */
  default Optional<String> emailFor(UserHandle handle) {
    return Optional.empty();
  }

  /** Read-only projection of host-app user state pk-auth needs for ceremonies and admin flows. */
  record UserView(
      UserHandle handle,
      String username,
      String displayName,
      boolean emailVerified,
      boolean phoneVerified) {
    public UserView {
      Objects.requireNonNull(handle, "handle");
      Objects.requireNonNull(username, "username");
      Objects.requireNonNull(displayName, "displayName");
    }
  }
}
