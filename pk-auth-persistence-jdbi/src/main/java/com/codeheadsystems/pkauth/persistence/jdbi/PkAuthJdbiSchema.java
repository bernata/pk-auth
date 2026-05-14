// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import javax.sql.DataSource;
import org.flywaydb.core.Flyway;

/**
 * Convenience helper to run pk-auth's Flyway migrations against a {@link DataSource}. Demo apps and
 * integration tests use this; host apps that already manage Flyway themselves can configure the
 * {@code db/migration} location into their own setup instead.
 */
public final class PkAuthJdbiSchema {

  private PkAuthJdbiSchema() {}

  /** Runs every pk-auth migration on the supplied {@code dataSource}. Idempotent. */
  public static void migrate(DataSource dataSource) {
    Flyway.configure().dataSource(dataSource).locations("classpath:db/migration").load().migrate();
  }
}
