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
  public void consume(String codeId, Instant consumedAt) {
    byId.computeIfPresent(
        codeId,
        (k, existing) ->
            new StoredBackupCode(
                existing.codeId(),
                existing.userHandle(),
                existing.hashedCode(),
                true,
                existing.createdAt(),
                consumedAt));
  }

  @Override
  public void deleteByUserHandle(UserHandle userHandle) {
    byId.values().removeIf(s -> s.userHandle().equals(userHandle));
  }
}
