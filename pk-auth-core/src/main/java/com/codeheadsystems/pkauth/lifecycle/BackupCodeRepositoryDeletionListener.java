// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.lifecycle;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import java.util.Objects;

/**
 * Bridges {@link BackupCodeRepository#deleteByUserHandle(UserHandle)} into the {@link
 * UserDeletionService} fan-out.
 *
 * @since 1.1.0
 */
public final class BackupCodeRepositoryDeletionListener implements UserDeletionListener {

  private final BackupCodeRepository repository;

  public BackupCodeRepositoryDeletionListener(BackupCodeRepository repository) {
    this.repository = Objects.requireNonNull(repository, "repository");
  }

  @Override
  public void onUserDeleted(UserHandle userHandle) {
    repository.deleteByUserHandle(userHandle);
  }
}
