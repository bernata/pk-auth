// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.jdbi.v3.core.Jdbi;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Shared Testcontainers Postgres fixture. Started once per JVM and reused across tests via
 * Testcontainers' reuse mode. Flyway migrations run during {@link #ready()}.
 */
public final class PostgresFixture {

  private static final PostgreSQLContainer<?> CONTAINER =
      new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
          .withDatabaseName("pkauth")
          .withUsername("pkauth")
          .withPassword("pkauth-test")
          .withReuse(true);

  private static HikariDataSource dataSource;
  private static Jdbi jdbi;

  private PostgresFixture() {}

  /** Lazily starts the container and runs migrations; returns the shared Jdbi handle. */
  public static synchronized Jdbi ready() {
    if (jdbi != null) {
      return jdbi;
    }
    if (!CONTAINER.isRunning()) {
      CONTAINER.start();
    }
    HikariConfig cfg = new HikariConfig();
    cfg.setJdbcUrl(CONTAINER.getJdbcUrl());
    cfg.setUsername(CONTAINER.getUsername());
    cfg.setPassword(CONTAINER.getPassword());
    cfg.setMaximumPoolSize(4);
    dataSource = new HikariDataSource(cfg);
    PkAuthJdbiSchema.migrateForDevelopment(dataSource);
    jdbi = Jdbi.create(dataSource);
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  if (dataSource != null) {
                    dataSource.close();
                  }
                }));
    return jdbi;
  }

  /** Truncates every pk-auth table so tests start from a clean state. */
  public static void reset() {
    ready();
    jdbi.useHandle(
        h ->
            h.execute(
                "TRUNCATE TABLE credentials, challenges, users, backup_codes, otp_codes,"
                    + " pkauth_audit_events RESTART IDENTITY CASCADE"));
  }
}
