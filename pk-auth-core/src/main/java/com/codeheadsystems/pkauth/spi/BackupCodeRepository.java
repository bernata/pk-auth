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
   * Marks the supplied code id as consumed. Implementations should treat double-consume as a no-op.
   */
  void consume(String codeId, Instant consumedAt);

  /** Deletes every backup code for a user — used by {@code regenerateAll}. */
  void deleteByUserHandle(UserHandle userHandle);
}
