// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.backupcodes;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.testkit.InMemoryBackupCodeRepository;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BackupCodeServiceTest {

  private static final Instant NOW = Instant.parse("2026-05-14T12:00:00Z");
  private InMemoryBackupCodeRepository repository;
  private BackupCodeService service;

  @BeforeEach
  void setUp() {
    repository = new InMemoryBackupCodeRepository();
    // Light Argon2 parameters to keep tests fast.
    Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    service =
        new BackupCodeService(
            repository,
            ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC)),
            new SecureRandom(),
            argon2,
            /* iterations */ 1,
            /* memory */ 1024,
            /* parallelism */ 1,
            /* codeCount */ 5);
  }

  @Test
  void generateProducesNDistinctTenCharCodes() {
    UserHandle user = UserHandle.of(new byte[] {1, 2, 3});
    List<String> codes = service.generate(user);
    assertThat(codes).hasSize(5);
    assertThat(codes).allMatch(c -> c.length() == BackupCodeService.CODE_LENGTH);
    assertThat(codes).doesNotHaveDuplicates();
    assertThat(repository.findByUserHandle(user)).hasSize(5);
  }

  @Test
  void verifyConsumesCodeOnFirstMatch() {
    UserHandle user = UserHandle.of(new byte[] {1, 2, 3});
    List<String> codes = service.generate(user);
    String first = codes.get(0);

    assertThat(service.verify(user, first)).isTrue();
    assertThat(service.remainingCount(user)).isEqualTo(4);
    assertThat(service.verify(user, first)).isFalse(); // already consumed
  }

  @Test
  void verifyRejectsUnknownCode() {
    UserHandle user = UserHandle.of(new byte[] {1, 2, 3});
    service.generate(user);
    assertThat(service.verify(user, "WRONGCODES")).isFalse();
    assertThat(service.remainingCount(user)).isEqualTo(5);
  }

  @Test
  void regenerateAllDeletesPriorAndIssuesFreshSet() {
    UserHandle user = UserHandle.of(new byte[] {1, 2, 3});
    List<String> first = service.generate(user);
    service.verify(user, first.get(0));

    List<String> second = service.regenerateAll(user);
    assertThat(second).hasSize(5);
    assertThat(service.remainingCount(user)).isEqualTo(5);
    // None of the first batch should verify anymore.
    for (String oldCode : first) {
      assertThat(service.verify(user, oldCode)).isFalse();
    }
  }
}
