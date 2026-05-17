// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.lifecycle;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import java.util.Objects;

/**
 * Bridges {@link OtpRepository#deleteByUserHandle(UserHandle)} into the {@link UserDeletionService}
 * fan-out.
 *
 * @since 1.1.0
 */
public final class OtpRepositoryDeletionListener implements UserDeletionListener {

  private final OtpRepository repository;

  public OtpRepositoryDeletionListener(OtpRepository repository) {
    this.repository = Objects.requireNonNull(repository, "repository");
  }

  @Override
  public void onUserDeleted(UserHandle userHandle) {
    repository.deleteByUserHandle(userHandle);
  }
}
