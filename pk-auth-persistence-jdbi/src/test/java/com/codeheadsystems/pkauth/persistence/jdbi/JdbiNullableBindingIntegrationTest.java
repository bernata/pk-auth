// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.refresh.RefreshTokenRecord;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository.StoredBackupCode;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Optional;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Regression coverage for the 1.1.0 binding bug: nullable typed columns (UUID, TIMESTAMPTZ, BYTEA)
 * bound via plain {@code .bind(name, null)} hit JDBI's untyped-null fallback (Types.VARCHAR), which
 * Postgres rejects against non-string column types.
 *
 * <p>The fixture uses a vanilla {@link Jdbi} (no {@code setUntypedNullArgument} workaround), so
 * these tests fail at save() against the unpatched code and pass once the repositories switch to
 * {@code bindByType}.
 */
@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class JdbiNullableBindingIntegrationTest {

  private Jdbi jdbi;
  private JdbiCredentialRepository credentials;
  private JdbiRefreshTokenRepository refreshTokens;
  private JdbiBackupCodeRepository backupCodes;

  @BeforeEach
  void setUp() {
    jdbi = PostgresFixture.ready();
    PostgresFixture.reset();
    credentials = new JdbiCredentialRepository(jdbi);
    refreshTokens = new JdbiRefreshTokenRepository(jdbi);
    backupCodes = new JdbiBackupCodeRepository(jdbi);
  }

  @Test
  void credentialSavedWithNullAaguidAndNullLastUsedAt() {
    // Platform authenticators (Touch ID, Windows Hello) and attestation=none ceremonies produce
    // a CredentialRecord with aaguid=null. Pre-patch this failed with:
    //   ERROR: column "aaguid" is of type uuid but expression is of type character varying
    UserHandle user = UserHandle.random();
    CredentialId credentialId = CredentialId.of(new byte[] {1, 2, 3, 4});
    CredentialRecord record =
        new CredentialRecord(
            credentialId,
            user,
            new byte[] {10, 11, 12},
            0L,
            "Touch ID",
            null,
            EnumSet.noneOf(Transport.class),
            false,
            false,
            Instant.parse("2026-05-17T12:00:00Z"),
            null);

    credentials.save(record);

    var loaded = credentials.findByCredentialId(credentialId).orElseThrow();
    assertThat(loaded.aaguid()).isNull();
    assertThat(loaded.lastUsedAt()).isNull();
  }

  @Test
  void refreshTokenCreatedWithNullUsedAtAndNullRevokedAt() {
    UserHandle user = UserHandle.random();
    Instant now = Instant.parse("2026-05-17T12:00:00Z");
    RefreshTokenRecord token =
        new RefreshTokenRecord(
            "rid-1",
            new byte[] {1, 2, 3},
            user,
            "aud-default",
            Optional.empty(),
            "fam-1",
            Optional.empty(),
            now,
            now.plusSeconds(3600),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            java.util.List.of("user"));

    refreshTokens.create(token);

    var loaded = refreshTokens.findByRefreshId("rid-1").orElseThrow();
    assertThat(loaded.usedAt()).isEmpty();
    assertThat(loaded.revokedAt()).isEmpty();
    assertThat(loaded.revokedReason()).isEmpty();
  }

  @Test
  void backupCodeSavedWithNullConsumedAt() {
    UserHandle user = UserHandle.random();
    Instant now = Instant.parse("2026-05-17T12:00:00Z");

    backupCodes.save(new StoredBackupCode("c1", user, "hash1", false, now, null));

    var active = backupCodes.findByUserHandle(user);
    assertThat(active).hasSize(1);
    assertThat(active.get(0).consumedAt()).isNull();
  }
}
