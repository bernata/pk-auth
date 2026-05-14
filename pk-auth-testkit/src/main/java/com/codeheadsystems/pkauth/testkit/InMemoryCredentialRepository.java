// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Map-backed {@link CredentialRepository} suitable for unit tests and demo bootstraps. */
public final class InMemoryCredentialRepository implements CredentialRepository {

  private final Map<ByteBuffer, CredentialRecord> byCredentialId = new ConcurrentHashMap<>();

  public InMemoryCredentialRepository() {}

  @Override
  public void save(CredentialRecord record) {
    ByteBuffer key = ByteBuffer.wrap(record.credentialId());
    if (byCredentialId.putIfAbsent(key, record) != null) {
      throw new IllegalStateException("Duplicate credential id");
    }
  }

  @Override
  public Optional<CredentialRecord> findByCredentialId(byte[] credentialId) {
    return Optional.ofNullable(byCredentialId.get(ByteBuffer.wrap(credentialId)));
  }

  @Override
  public List<CredentialRecord> findByUserHandle(UserHandle userHandle) {
    return byCredentialId.values().stream().filter(c -> c.userHandle().equals(userHandle)).toList();
  }

  @Override
  public void updateSignCount(byte[] credentialId, long newCount, Instant lastUsedAt) {
    byCredentialId.computeIfPresent(
        ByteBuffer.wrap(credentialId),
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
  public void updateLabel(byte[] credentialId, String label) {
    byCredentialId.computeIfPresent(
        ByteBuffer.wrap(credentialId),
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
  public void delete(byte[] credentialId) {
    byCredentialId.remove(ByteBuffer.wrap(credentialId));
  }
}
