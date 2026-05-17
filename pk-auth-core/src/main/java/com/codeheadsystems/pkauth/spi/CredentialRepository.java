// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spi;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Persistent storage for passkey credentials. Implemented by the JDBI and DynamoDB persistence
 * modules (and by {@code InMemoryEverything} in the testkit).
 */
public interface CredentialRepository {

  /** Inserts a new credential record. Implementations must reject duplicates on credentialId. */
  void save(CredentialRecord record);

  Optional<CredentialRecord> findByCredentialId(CredentialId credentialId);

  List<CredentialRecord> findByUserHandle(UserHandle userHandle);

  void updateSignCount(CredentialId credentialId, long newCount, Instant lastUsedAt);

  void updateLabel(CredentialId credentialId, String label);

  /**
   * Hard-deletes the credential row. Implementations must remove the row outright; soft-delete
   * (e.g. a {@code revoked_at} marker) is no longer permitted on this SPI.
   *
   * <p>Audit history for credential deletions is the responsibility of the host's structured log
   * pipeline. pk-auth's {@code DefaultAdminService.deleteCredential} emits a {@code
   * pkauth.credential.deleted} INFO log event (containing the base64url credential id and user
   * handle) around every call to this method; consume that signal rather than persisting deletion
   * tombstones inside the credentials table.
   */
  void delete(CredentialId credentialId);

  /**
   * Hard-deletes every credential owned by the supplied user. Called by {@link
   * com.codeheadsystems.pkauth.lifecycle.UserDeletionService} during user-deletion fan-out; hosts
   * may also call it directly for bulk-revocation flows.
   *
   * <p>Returns the number of rows removed (best-effort; used for structured logging). Must be
   * idempotent — a call against a user with no remaining credentials returns {@code 0}.
   *
   * @since 1.1.0
   */
  int deleteByUserHandle(UserHandle userHandle);
}
