// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.RowMapper;

/** {@link OtpRepository} backed by the {@code otp_codes} table (Flyway V4). */
public final class JdbiOtpRepository implements OtpRepository {

  private final Jdbi jdbi;

  public JdbiOtpRepository(Jdbi jdbi) {
    this.jdbi = Objects.requireNonNull(jdbi, "jdbi");
  }

  @Override
  public void save(StoredOtp otp) {
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
  }

  @Override
  public Optional<StoredOtp> findLatestActive(UserHandle userHandle, String phoneE164) {
    return jdbi.withHandle(
        h ->
            h.createQuery(
                    "SELECT * FROM otp_codes WHERE user_handle = :uh AND phone_e164 = :phone"
                        + " AND consumed = FALSE"
                        + " ORDER BY created_at DESC LIMIT 1")
                .bind("uh", userHandle.value())
                .bind("phone", phoneE164)
                .map(MAPPER)
                .findFirst());
  }

  @Override
  public int incrementAttempts(String otpId) {
    return jdbi.withHandle(
        h -> {
          h.createUpdate("UPDATE otp_codes SET attempts = attempts + 1 WHERE otp_id = :oid")
              .bind("oid", otpId)
              .execute();
          return h.createQuery("SELECT attempts FROM otp_codes WHERE otp_id = :oid")
              .bind("oid", otpId)
              .mapTo(Integer.class)
              .one();
        });
  }

  @Override
  public void consume(String otpId) {
    jdbi.useHandle(
        h ->
            h.createUpdate("UPDATE otp_codes SET consumed = TRUE WHERE otp_id = :oid")
                .bind("oid", otpId)
                .execute());
  }

  @Override
  public int countSince(UserHandle userHandle, String phoneE164, Instant since) {
    return jdbi.withHandle(
        h ->
            h.createQuery(
                    "SELECT COUNT(*) FROM otp_codes WHERE user_handle = :uh AND phone_e164 = :phone"
                        + " AND created_at >= :since")
                .bind("uh", userHandle.value())
                .bind("phone", phoneE164)
                .bind("since", OffsetDateTime.ofInstant(since, ZoneOffset.UTC))
                .mapTo(Integer.class)
                .one());
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
