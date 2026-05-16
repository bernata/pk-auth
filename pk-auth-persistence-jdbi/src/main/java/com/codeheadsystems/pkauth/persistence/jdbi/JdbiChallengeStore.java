// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.JdbiException;
import org.jdbi.v3.core.mapper.RowMapper;

/**
 * {@link ChallengeStore} backed by the {@code challenges} table. {@code takeOnce} uses a single
 * {@code DELETE … RETURNING} statement so single-use semantics are atomic at the database level.
 */
public final class JdbiChallengeStore implements ChallengeStore {

  private final Jdbi jdbi;

  public JdbiChallengeStore(Jdbi jdbi) {
    this.jdbi = Objects.requireNonNull(jdbi, "jdbi");
  }

  @Override
  public void put(ChallengeId id, ChallengeRecord record, Duration ttl) {
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(record, "record");
    Objects.requireNonNull(ttl, "ttl");
    if (ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("ttl must be strictly positive, got " + ttl);
    }
    wrap(
        "challenges.put",
        () -> {
          jdbi.useHandle(
              h ->
                  h.createUpdate(
                          "INSERT INTO challenges (id, challenge, purpose, user_handle,"
                              + " expires_at)"
                              + " VALUES (:id, :challenge, :purpose, :uh, :expiresAt)"
                              + " ON CONFLICT (id) DO UPDATE SET challenge = EXCLUDED.challenge,"
                              + " purpose = EXCLUDED.purpose, user_handle = EXCLUDED.user_handle,"
                              + " expires_at = EXCLUDED.expires_at")
                      .bind("id", id.value())
                      .bind("challenge", record.challenge())
                      .bind("purpose", record.purpose().name())
                      .bind("uh", record.userHandle() == null ? null : record.userHandle().value())
                      .bind(
                          "expiresAt", OffsetDateTime.ofInstant(record.expiresAt(), ZoneOffset.UTC))
                      .execute());
          return null;
        });
  }

  @Override
  public Optional<ChallengeRecord> takeOnce(ChallengeId id) {
    return wrap(
        "challenges.takeOnce",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery(
                            "DELETE FROM challenges WHERE id = :id AND expires_at > NOW()"
                                + " RETURNING challenge, purpose, user_handle, expires_at")
                        .bind("id", id.value())
                        .map(MAPPER)
                        .findFirst()));
  }

  /**
   * Runs {@code body} and wraps any {@link JdbiException} in a {@link PkAuthPersistenceException}
   * so adapter exception mappers can produce a uniform 503.
   */
  private static <T> T wrap(String op, Supplier<T> body) {
    try {
      return body.get();
    } catch (PkAuthPersistenceException already) {
      throw already;
    } catch (JdbiException e) {
      throw new PkAuthPersistenceException(op, e.getMessage(), e);
    }
  }

  private static final RowMapper<ChallengeRecord> MAPPER = (rs, ctx) -> readRow(rs);

  private static ChallengeRecord readRow(ResultSet rs) throws SQLException {
    byte[] challenge = rs.getBytes("challenge");
    ChallengeRecord.Purpose purpose = ChallengeRecord.Purpose.valueOf(rs.getString("purpose"));
    byte[] userHandleBytes = rs.getBytes("user_handle");
    UserHandle userHandle = userHandleBytes == null ? null : UserHandle.of(userHandleBytes);
    OffsetDateTime expiresAt = rs.getObject("expires_at", OffsetDateTime.class);
    return new ChallengeRecord(challenge, purpose, userHandle, expiresAt.toInstant());
  }
}
