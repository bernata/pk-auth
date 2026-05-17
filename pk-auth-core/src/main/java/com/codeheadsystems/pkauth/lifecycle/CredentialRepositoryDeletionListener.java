// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.lifecycle;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import java.util.Objects;

/**
 * Bridges {@link CredentialRepository#deleteByUserHandle(UserHandle)} into the {@link
 * UserDeletionService} fan-out. Adapter modules register this bean alongside other listeners.
 *
 * @since 1.1.0
 */
public final class CredentialRepositoryDeletionListener implements UserDeletionListener {

  private final CredentialRepository repository;

  public CredentialRepositoryDeletionListener(CredentialRepository repository) {
    this.repository = Objects.requireNonNull(repository, "repository");
  }

  @Override
  public void onUserDeleted(UserHandle userHandle) {
    repository.deleteByUserHandle(userHandle);
  }
}
