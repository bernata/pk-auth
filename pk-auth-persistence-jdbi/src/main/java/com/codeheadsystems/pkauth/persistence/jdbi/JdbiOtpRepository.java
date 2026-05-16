// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.function.Supplier;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.JdbiException;
import org.jdbi.v3.core.mapper.RowMapper;

/** {@link OtpRepository} backed by the {@code otp_codes} table (Flyway V4). */
public final class JdbiOtpRepository implements OtpRepository {

  private final Jdbi jdbi;

  public JdbiOtpRepository(Jdbi jdbi) {
    this.jdbi = Objects.requireNonNull(jdbi, "jdbi");
  }

  @Override
  public void save(StoredOtp otp) {
    wrap(
        "otp.save",
        () -> {
          jdbi.useHandle(
              h ->
                  h.createUpdate(
                          "INSERT INTO otp_codes (otp_id, user_handle, phone_e164, hashed_code,"
                              + " attempts, max_attempts, consumed, expires_at, created_at)"
                              + " VALUES (:oid, :uh, :phone, :hash, :attempts, :max, :consumed,"
                              + " :expiresAt, :createdAt)")
                      .bind("oid", otp.otpId())
                      .bind("uh", otp.userHandle().value())
                      .bind("phone", otp.phoneE164())
                      .bind("hash", otp.hashedCode())
                      .bind("attempts", otp.attempts())
                      .bind("max", otp.maxAttempts())
                      .bind("consumed", otp.consumed())
                      .bind("expiresAt", OffsetDateTime.ofInstant(otp.expiresAt(), ZoneOffset.UTC))
                      .bind("createdAt", OffsetDateTime.ofInstant(otp.createdAt(), ZoneOffset.UTC))
                      .execute());
          return null;
        });
  }

  @Override
  public Optional<StoredOtp> findLatestActive(UserHandle userHandle, String phoneE164) {
    return wrap(
        "otp.findLatestActive",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery(
                            "SELECT * FROM otp_codes WHERE user_handle = :uh AND phone_e164 ="
                                + " :phone AND consumed = FALSE"
                                + " ORDER BY created_at DESC LIMIT 1")
                        .bind("uh", userHandle.value())
                        .bind("phone", phoneE164)
                        .map(MAPPER)
                        .findFirst()));
  }

  @Override
  public OptionalInt incrementAttempts(UserHandle userHandle, String otpId) {
    return wrap(
        "otp.incrementAttempts",
        () ->
            jdbi.withHandle(
                h -> {
                  // Increment unconditionally. A prior guarded `attempts < max_attempts` made the
                  // UPDATE a no-op once the cap was reached, which let callers loop verification
                  // forever within the TTL (the post-increment value never exceeded max_attempts,
                  // so the cap check in OtpService never tripped). Matches the DynamoDB impl,
                  // which also increments without a guard. Caller is required to compare the
                  // returned count against maxAttempts.
                  int updated =
                      h.createUpdate(
                              "UPDATE otp_codes SET attempts = attempts + 1"
                                  + " WHERE user_handle = :uh AND otp_id = :oid")
                          .bind("uh", userHandle.value())
                          .bind("oid", otpId)
                          .execute();
                  if (updated == 0) {
                    // SPI contract: empty signals "no such row".
                    return OptionalInt.empty();
                  }
                  Optional<Integer> current =
                      h.createQuery(
                              "SELECT attempts FROM otp_codes"
                                  + " WHERE user_handle = :uh AND otp_id = :oid")
                          .bind("uh", userHandle.value())
                          .bind("oid", otpId)
                          .mapTo(Integer.class)
                          .findFirst();
                  return current.map(OptionalInt::of).orElse(OptionalInt.empty());
                }));
  }

  @Override
  public boolean consume(UserHandle userHandle, String otpId) {
    return wrap(
        "otp.consume",
        () ->
            jdbi.withHandle(
                h ->
                    h.createUpdate(
                                "UPDATE otp_codes SET consumed = TRUE"
                                    + " WHERE user_handle = :uh AND otp_id = :oid"
                                    + "       AND consumed = FALSE")
                            .bind("uh", userHandle.value())
                            .bind("oid", otpId)
                            .execute()
                        == 1));
  }

  @Override
  public int countSince(UserHandle userHandle, String phoneE164, Instant since) {
    return wrap(
        "otp.countSince",
        () ->
            jdbi.withHandle(
                h ->
                    h.createQuery(
                            "SELECT COUNT(*) FROM otp_codes WHERE user_handle = :uh AND phone_e164"
                                + " = :phone AND created_at >= :since")
                        .bind("uh", userHandle.value())
                        .bind("phone", phoneE164)
                        .bind("since", OffsetDateTime.ofInstant(since, ZoneOffset.UTC))
                        .mapTo(Integer.class)
                        .one()));
  }

  /**
   * Runs {@code body} and wraps any {@link JdbiException} in a {@link PkAuthPersistenceException}
   * so adapter exception mappers can produce a uniform 503. Existing {@link
   * PkAuthPersistenceException} instances are re-thrown unchanged.
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

  private static final RowMapper<StoredOtp> MAPPER = (rs, ctx) -> readRow(rs);

  private static StoredOtp readRow(ResultSet rs) throws SQLException {
    return new StoredOtp(
        rs.getString("otp_id"),
        UserHandle.of(rs.getBytes("user_handle")),
        rs.getString("phone_e164"),
        rs.getString("hashed_code"),
        rs.getInt("attempts"),
        rs.getInt("max_attempts"),
        rs.getBoolean("consumed"),
        rs.getObject("created_at", OffsetDateTime.class).toInstant(),
        rs.getObject("expires_at", OffsetDateTime.class).toInstant());
  }
}
