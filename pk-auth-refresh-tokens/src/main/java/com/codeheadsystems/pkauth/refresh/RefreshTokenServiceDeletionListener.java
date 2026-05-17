// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.lifecycle.UserDeletionListener;
import java.util.Objects;

/**
 * Bridges {@link RefreshTokenService#revokeAllForUser(UserHandle, RevokeReason)} into the {@link
 * com.codeheadsystems.pkauth.lifecycle.UserDeletionService} fan-out. Adapters register this
 * listener whenever a {@link RefreshTokenService} bean is wired so refresh families are revoked as
 * part of user deletion.
 *
 * @since 1.1.0
 */
public final class RefreshTokenServiceDeletionListener implements UserDeletionListener {

  private final RefreshTokenService service;

  public RefreshTokenServiceDeletionListener(RefreshTokenService service) {
    this.service = Objects.requireNonNull(service, "service");
  }

  @Override
  public void onUserDeleted(UserHandle userHandle) {
    service.revokeAllForUser(userHandle, RevokeReason.USER_DELETED);
  }
}
