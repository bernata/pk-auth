// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.DuplicateCredentialException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Map-backed {@link CredentialRepository} suitable for unit tests and demo bootstraps. */
public final class InMemoryCredentialRepository implements CredentialRepository {

  private final Map<CredentialId, CredentialRecord> byCredentialId = new ConcurrentHashMap<>();

  public InMemoryCredentialRepository() {}

  @Override
  public void save(CredentialRecord record) {
    if (byCredentialId.putIfAbsent(record.credentialId(), record) != null) {
      throw new DuplicateCredentialException("Duplicate credential id");
    }
  }

  @Override
  public Optional<CredentialRecord> findByCredentialId(CredentialId credentialId) {
    return Optional.ofNullable(byCredentialId.get(credentialId));
  }

  @Override
  public List<CredentialRecord> findByUserHandle(UserHandle userHandle) {
    return byCredentialId.values().stream().filter(c -> c.userHandle().equals(userHandle)).toList();
  }

  @Override
  public void updateSignCount(CredentialId credentialId, long newCount, Instant lastUsedAt) {
    byCredentialId.computeIfPresent(
        credentialId,
        (k, existing) ->
            new CredentialRecord(
                existing.credentialId(),
                existing.userHandle(),
                existing.publicKeyCose(),
                newCount,
                existing.label(),
                existing.aaguid(),
                existing.transports(),
                existing.backupEligible(),
                existing.backupState(),
                existing.createdAt(),
                lastUsedAt));
  }

  @Override
  public void updateLabel(CredentialId credentialId, String label) {
    byCredentialId.computeIfPresent(
        credentialId,
        (k, existing) ->
            new CredentialRecord(
                existing.credentialId(),
                existing.userHandle(),
                existing.publicKeyCose(),
                existing.signCount(),
                label,
                existing.aaguid(),
                existing.transports(),
                existing.backupEligible(),
                existing.backupState(),
                existing.createdAt(),
                existing.lastUsedAt()));
  }

  @Override
  public void delete(CredentialId credentialId) {
    byCredentialId.remove(credentialId);
  }

  @Override
  public int deleteByUserHandle(UserHandle userHandle) {
    int[] removed = {0};
    byCredentialId
        .entrySet()
        .removeIf(
            e -> {
              if (e.getValue().userHandle().equals(userHandle)) {
                removed[0]++;
                return true;
              }
              return false;
            });
    return removed[0];
  }
}
