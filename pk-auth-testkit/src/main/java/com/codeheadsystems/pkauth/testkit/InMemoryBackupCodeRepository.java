// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory {@link BackupCodeRepository} for unit tests and demo bootstrap. */
public final class InMemoryBackupCodeRepository implements BackupCodeRepository {

  private final Map<String, StoredBackupCode> byId = new ConcurrentHashMap<>();

  public InMemoryBackupCodeRepository() {}

  @Override
  public void save(StoredBackupCode code) {
    byId.put(code.codeId(), code);
  }

  @Override
  public List<StoredBackupCode> findByUserHandle(UserHandle userHandle) {
    return byId.values().stream().filter(s -> s.userHandle().equals(userHandle)).toList();
  }

  @Override
  public void consume(UserHandle userHandle, String codeId, Instant consumedAt) {
    byId.computeIfPresent(
        codeId,
        (k, existing) -> {
          if (!existing.userHandle().equals(userHandle)) {
            return existing;
          }
          return new StoredBackupCode(
              existing.codeId(),
              existing.userHandle(),
              existing.hashedCode(),
              true,
              existing.createdAt(),
              consumedAt);
        });
  }

  @Override
  public void deleteByUserHandle(UserHandle userHandle) {
    byId.values().removeIf(s -> s.userHandle().equals(userHandle));
  }

  /**
   * Atomically replaces all codes for a user inside a synchronized block so that concurrent readers
   * never observe a partially-replaced set.
   */
  @Override
  public synchronized void replaceAll(UserHandle userHandle, List<StoredBackupCode> records) {
    byId.values().removeIf(s -> s.userHandle().equals(userHandle));
    for (StoredBackupCode record : records) {
      byId.put(record.codeId(), record);
    }
  }
}
