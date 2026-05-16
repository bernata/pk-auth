// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import java.time.Instant;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;

/** Direct CRUD against the JDBI backup-code and OTP repositories. */
@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class JdbiAltFlowsIntegrationTest {

  private Jdbi jdbi;
  private JdbiBackupCodeRepository backupCodes;
  private JdbiOtpRepository otp;

  @BeforeEach
  void setUp() {
    jdbi = PostgresFixture.ready();
    PostgresFixture.reset();
    backupCodes = new JdbiBackupCodeRepository(jdbi);
    otp = new JdbiOtpRepository(jdbi);
  }

  @Test
  void backupCodeRoundTrip() {
    UserHandle user = UserHandle.random();
    Instant now = Instant.parse("2026-05-14T12:00:00Z");
    backupCodes.save(
        new BackupCodeRepository.StoredBackupCode("c1", user, "hash1", false, now, null));
    backupCodes.save(
        new BackupCodeRepository.StoredBackupCode("c2", user, "hash2", false, now, null));

    assertThat(backupCodes.findByUserHandle(user)).hasSize(2);

    // Consuming a code soft-deletes it (sets revoked_at); active query returns only remaining code.
    backupCodes.consume(user, "c1", now.plusSeconds(60));
    var active = backupCodes.findByUserHandle(user);
    assertThat(active).hasSize(1);
    assertThat(active.get(0).consumed()).isFalse();

    // Soft-deleting the remaining active codes makes findByUserHandle return empty.
    backupCodes.deleteByUserHandle(user);
    assertThat(backupCodes.findByUserHandle(user)).isEmpty();
  }

  @Test
  void incrementAttempts_doesNotExceedMaxAttempts() {
    UserHandle user = UserHandle.random();
    Instant t0 = Instant.parse("2026-05-14T12:00:00Z");
    // max_attempts = 3; save with attempts already at 3 (at cap).
    otp.save(
        new OtpRepository.StoredOtp(
            "o-cap", user, "+15559990000", "hash", 3, 3, false, t0, t0.plusSeconds(300)));

    int result = otp.incrementAttempts(user, "o-cap");

    // Guard must prevent advancing past cap; returned value must remain 3.
    assertThat(result).isEqualTo(3);
    var stored = otp.findLatestActive(user, "+15559990000").orElseThrow();
    assertThat(stored.attempts()).isEqualTo(3);
  }

  @Test
  void incrementAttempts_advancesWhenBelowCap() {
    UserHandle user = UserHandle.random();
    Instant t0 = Instant.parse("2026-05-14T12:00:00Z");
    otp.save(
        new OtpRepository.StoredOtp(
            "o-inc", user, "+15558880000", "hash", 2, 3, false, t0, t0.plusSeconds(300)));

    int result = otp.incrementAttempts(user, "o-inc");

    assertThat(result).isEqualTo(3);
    var stored = otp.findLatestActive(user, "+15558880000").orElseThrow();
    assertThat(stored.attempts()).isEqualTo(3);
  }

  @Test
  void otpRoundTripAndCountSince() {
    UserHandle user = UserHandle.random();
    Instant t0 = Instant.parse("2026-05-14T12:00:00Z");
    otp.save(
        new OtpRepository.StoredOtp(
            "o1", user, "+15551234567", "hash", 0, 5, false, t0, t0.plusSeconds(300)));
    otp.save(
        new OtpRepository.StoredOtp(
            "o2",
            user,
            "+15551234567",
            "hash",
            0,
            5,
            false,
            t0.plusSeconds(60),
            t0.plusSeconds(360)));

    var active = otp.findLatestActive(user, "+15551234567").orElseThrow();
    assertThat(active.otpId()).isEqualTo("o2");

    otp.incrementAttempts(user, "o2");
    otp.incrementAttempts(user, "o2");
    var refreshed = otp.findLatestActive(user, "+15551234567").orElseThrow();
    assertThat(refreshed.attempts()).isEqualTo(2);

    assertThat(otp.countSince(user, "+15551234567", t0.minusSeconds(10))).isEqualTo(2);
    assertThat(otp.countSince(user, "+15551234567", t0.plusSeconds(120))).isZero();

    otp.consume(user, "o2");
    var noActive = otp.findLatestActive(user, "+15551234567");
    assertThat(noActive).hasValueSatisfying(o -> assertThat(o.otpId()).isEqualTo("o1"));
  }
}
