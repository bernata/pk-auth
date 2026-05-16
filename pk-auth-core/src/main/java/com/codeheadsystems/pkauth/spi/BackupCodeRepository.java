// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/** Persistent storage for backup-code hashes (brief §6.3). One row per issued code. */
public interface BackupCodeRepository {

  /** Stored representation of a single backup code. The plaintext is never persisted. */
  record StoredBackupCode(
      String codeId,
      UserHandle userHandle,
      String hashedCode,
      boolean consumed,
      Instant createdAt,
      @Nullable Instant consumedAt) {
    public StoredBackupCode {
      Objects.requireNonNull(codeId, "codeId");
      Objects.requireNonNull(userHandle, "userHandle");
      Objects.requireNonNull(hashedCode, "hashedCode");
      Objects.requireNonNull(createdAt, "createdAt");
    }
  }

  /** Inserts a freshly issued backup code. */
  void save(StoredBackupCode code);

  /** Lists every backup code for a user, consumed or not. */
  List<StoredBackupCode> findByUserHandle(UserHandle userHandle);

  /**
   * Marks the supplied code id as consumed for the given user. The {@code userHandle} is the
   * partition under which the code lives; implementations use it to address the row directly
   * instead of scanning. Implementations should treat double-consume as a no-op.
   */
  void consume(UserHandle userHandle, String codeId, Instant consumedAt);

  /** Deletes every backup code for a user — used by {@code regenerateAll}. */
  void deleteByUserHandle(UserHandle userHandle);

  /**
   * Atomically replaces all backup codes for a user: deletes every existing code and inserts the
   * supplied records in a single logical unit of work.
   *
   * <p>The default implementation calls {@link #deleteByUserHandle} followed by individual {@link
   * #save} calls, which is NOT transactional. Production implementations SHOULD override this
   * method to execute inside a database transaction so that a mid-loop failure cannot leave the
   * user with a partial or empty set of codes.
   */
  default void replaceAll(UserHandle userHandle, List<StoredBackupCode> records) {
    deleteByUserHandle(userHandle);
    for (StoredBackupCode record : records) {
      save(record);
    }
  }
}
