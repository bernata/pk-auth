// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.RowMapper;

/** {@link BackupCodeRepository} backed by the {@code backup_codes} table (Flyway V3). */
public final class JdbiBackupCodeRepository implements BackupCodeRepository {

  private final Jdbi jdbi;

  public JdbiBackupCodeRepository(Jdbi jdbi) {
    this.jdbi = Objects.requireNonNull(jdbi, "jdbi");
  }

  @Override
  public void save(StoredBackupCode code) {
    jdbi.useHandle(
        h ->
            h.createUpdate(
                    "INSERT INTO backup_codes (code_id, user_handle, hashed_code, consumed,"
                        + " consumed_at, created_at)"
                        + " VALUES (:cid, :uh, :hash, :consumed, :consumedAt, :createdAt)")
                .bind("cid", code.codeId())
                .bind("uh", code.userHandle().value())
                .bind("hash", code.hashedCode())
                .bind("consumed", code.consumed())
                .bind(
                    "consumedAt",
                    code.consumedAt() == null
                        ? null
                        : OffsetDateTime.ofInstant(code.consumedAt(), ZoneOffset.UTC))
                .bind("createdAt", OffsetDateTime.ofInstant(code.createdAt(), ZoneOffset.UTC))
                .execute());
  }

  @Override
  public List<StoredBackupCode> findByUserHandle(UserHandle userHandle) {
    return jdbi.withHandle(
        h ->
            h.createQuery("SELECT * FROM backup_codes WHERE user_handle = :uh ORDER BY created_at")
                .bind("uh", userHandle.value())
                .map(MAPPER)
                .list());
  }

  @Override
  public void consume(String codeId, Instant consumedAt) {
    jdbi.useHandle(
        h ->
            h.createUpdate(
                    "UPDATE backup_codes SET consumed = TRUE, consumed_at = :consumedAt"
                        + " WHERE code_id = :cid AND consumed = FALSE")
                .bind("consumedAt", OffsetDateTime.ofInstant(consumedAt, ZoneOffset.UTC))
                .bind("cid", codeId)
                .execute());
  }

  @Override
  public void deleteByUserHandle(UserHandle userHandle) {
    jdbi.useHandle(
        h ->
            h.createUpdate("DELETE FROM backup_codes WHERE user_handle = :uh")
                .bind("uh", userHandle.value())
                .execute());
  }

  private static final RowMapper<StoredBackupCode> MAPPER = (rs, ctx) -> readRow(rs);

  private static StoredBackupCode readRow(ResultSet rs) throws SQLException {
    OffsetDateTime consumedAt = rs.getObject("consumed_at", OffsetDateTime.class);
    return new StoredBackupCode(
        rs.getString("code_id"),
        UserHandle.of(rs.getBytes("user_handle")),
        rs.getString("hashed_code"),
        rs.getBoolean("consumed"),
        rs.getObject("created_at", OffsetDateTime.class).toInstant(),
        consumedAt == null ? null : consumedAt.toInstant());
  }
}
