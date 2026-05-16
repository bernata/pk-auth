// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
// Array import kept for the row-mapper path that reads back the text[] column.
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.RowMapper;

/**
 * {@link CredentialRepository} backed by the Phase 5 {@code credentials} table.
 *
 * <p>Since V6, credential deletion is a soft-delete: the row is retained with {@code revoked_at}
 * and {@code revoked_reason} set and an audit-event written to {@code pkauth_audit_events}. All
 * active-credential queries filter on {@code revoked_at IS NULL}.
 */
public final class JdbiCredentialRepository implements CredentialRepository {

  private static final String DEFAULT_REVOKE_REASON = "user_request";

  private final Jdbi jdbi;

  public JdbiCredentialRepository(Jdbi jdbi) {
    this.jdbi = Objects.requireNonNull(jdbi, "jdbi");
  }

  @Override
  public void save(CredentialRecord record) {
    int inserted =
        jdbi.withHandle(
            h ->
                h.createUpdate(
                        "INSERT INTO credentials (credential_id, user_handle, public_key_cose,"
                            + " sign_count, label, aaguid, transports, backup_eligible,"
                            + " backup_state, created_at, last_used_at)"
                            + " VALUES (:cid, :uh, :pk, :sc, :label, :aaguid, :transports,"
                            + " :be, :bs, :createdAt, :lastUsedAt)"
                            + " ON CONFLICT (credential_id) DO NOTHING")
                    .bind("cid", record.credentialId())
                    .bind("uh", record.userHandle().value())
                    .bind("pk", record.publicKeyCose())
                    .bind("sc", record.signCount())
                    .bind("label", record.label())
                    .bind("aaguid", record.aaguid())
                    .bindArray(
                        "transports",
                        String.class,
                        (Object[]) record.transports().toArray(new String[0]))
                    .bind("be", record.backupEligible())
                    .bind("bs", record.backupState())
                    .bind("createdAt", OffsetDateTime.ofInstant(record.createdAt(), ZoneOffset.UTC))
                    .bind(
                        "lastUsedAt",
                        record.lastUsedAt() == null
                            ? null
                            : OffsetDateTime.ofInstant(record.lastUsedAt(), ZoneOffset.UTC))
                    .execute());
    if (inserted == 0) {
      throw new IllegalStateException(
          "Duplicate credential id; refusing to overwrite an existing credential");
    }
  }

  /** Finds an active (not revoked) credential by id. */
  @Override
  public Optional<CredentialRecord> findByCredentialId(byte[] credentialId) {
    return jdbi.withHandle(
        h ->
            h.createQuery(
                    "SELECT * FROM credentials"
                        + " WHERE credential_id = :cid AND revoked_at IS NULL")
                .bind("cid", credentialId)
                .map(MAPPER)
                .findFirst());
  }

  /** Returns only active (not revoked) credentials for the given user handle. */
  @Override
  public List<CredentialRecord> findByUserHandle(UserHandle userHandle) {
    return jdbi.withHandle(
        h ->
            h.createQuery(
                    "SELECT * FROM credentials"
                        + " WHERE user_handle = :uh AND revoked_at IS NULL"
                        + " ORDER BY created_at")
                .bind("uh", userHandle.value())
                .map(MAPPER)
                .list());
  }

  @Override
  public void updateSignCount(byte[] credentialId, long newCount, Instant lastUsedAt) {
    // Guard against concurrent racing assertions overwriting a higher stored counter with a
    // lower one — that would silently defeat WebAuthn's clone-detection invariant. Only advance
    // the counter when the new value strictly exceeds the stored one.
    jdbi.useHandle(
        h ->
            h.createUpdate(
                    "UPDATE credentials SET sign_count = :sc, last_used_at = :lua"
                        + " WHERE credential_id = :cid AND sign_count < :sc"
                        + "   AND revoked_at IS NULL")
                .bind("sc", newCount)
                .bind("lua", OffsetDateTime.ofInstant(lastUsedAt, ZoneOffset.UTC))
                .bind("cid", credentialId)
                .execute());
  }

  @Override
  public void updateLabel(byte[] credentialId, String label) {
    jdbi.useHandle(
        h ->
            h.createUpdate(
                    "UPDATE credentials SET label = :label"
                        + " WHERE credential_id = :cid AND revoked_at IS NULL")
                .bind("label", label)
                .bind("cid", credentialId)
                .execute());
  }

  /**
   * Soft-deletes the credential with the default reason {@code "user_request"} and writes an
   * audit-event row.
   */
  @Override
  public void delete(byte[] credentialId) {
    delete(credentialId, DEFAULT_REVOKE_REASON);
  }

  /**
   * Soft-deletes the credential with the supplied {@code reason} (max 64 chars) and writes an
   * audit-event row.
   */
  public void delete(byte[] credentialId, String reason) {
    String safeReason = reason == null ? DEFAULT_REVOKE_REASON : reason;
    jdbi.useHandle(
        h -> {
          // Lookup user_handle before revoking so we can populate the audit event.
          byte[] userHandle =
              h.createQuery(
                      "SELECT user_handle FROM credentials"
                          + " WHERE credential_id = :cid AND revoked_at IS NULL")
                  .bind("cid", credentialId)
                  .mapTo(byte[].class)
                  .findFirst()
                  .orElse(null);

          h.createUpdate(
                  "UPDATE credentials"
                      + " SET revoked_at = NOW(), revoked_reason = :reason"
                      + " WHERE credential_id = :cid AND revoked_at IS NULL")
              .bind("reason", safeReason)
              .bind("cid", credentialId)
              .execute();

          h.createUpdate(
                  "INSERT INTO pkauth_audit_events"
                      + " (event_type, user_handle, subject_id, detail)"
                      + " VALUES ('credential_revoked', :uh, :subjectId, :detail)")
              .bind("uh", userHandle)
              .bind("subjectId", credentialIdHex(credentialId))
              .bind("detail", "reason=" + safeReason)
              .execute();
        });
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  /** Returns a hex string representation of the credential id for use as a readable subject_id. */
  private static String credentialIdHex(byte[] credentialId) {
    if (credentialId == null) {
      return null;
    }
    StringBuilder sb = new StringBuilder(credentialId.length * 2);
    for (byte b : credentialId) {
      sb.append(String.format("%02x", b));
    }
    // subject_id is VARCHAR(255); truncate if the credential id is unusually long.
    String hex = sb.toString();
    return hex.length() <= 255 ? hex : hex.substring(0, 255);
  }

  private static final RowMapper<CredentialRecord> MAPPER = (rs, ctx) -> readRow(rs);

  private static CredentialRecord readRow(ResultSet rs) throws SQLException {
    byte[] credentialId = rs.getBytes("credential_id");
    byte[] userHandle = rs.getBytes("user_handle");
    byte[] pk = rs.getBytes("public_key_cose");
    long sc = rs.getLong("sign_count");
    String label = rs.getString("label");
    UUID aaguid = (UUID) rs.getObject("aaguid");
    Set<String> transports = readTextArray(rs, "transports");
    boolean be = rs.getBoolean("backup_eligible");
    boolean bs = rs.getBoolean("backup_state");
    Instant createdAt = rs.getObject("created_at", OffsetDateTime.class).toInstant();
    OffsetDateTime lua = rs.getObject("last_used_at", OffsetDateTime.class);
    return new CredentialRecord(
        credentialId,
        UserHandle.of(userHandle),
        pk,
        sc,
        label,
        aaguid,
        transports,
        be,
        bs,
        createdAt,
        lua == null ? null : lua.toInstant());
  }

  private static Set<String> readTextArray(ResultSet rs, String column) throws SQLException {
    Array array = rs.getArray(column);
    if (array == null) {
      return Set.of();
    }
    Object raw = array.getArray();
    if (!(raw instanceof Object[] elements)) {
      return Set.of();
    }
    Set<String> out = new LinkedHashSet<>(elements.length);
    for (Object e : elements) {
      if (e != null) {
        out.add(e.toString());
      }
    }
    return out;
  }
}
