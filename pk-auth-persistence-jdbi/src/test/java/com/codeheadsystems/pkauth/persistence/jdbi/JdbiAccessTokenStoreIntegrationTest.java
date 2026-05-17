// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.testkit.AccessTokenStoreScenarios;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class JdbiAccessTokenStoreIntegrationTest {

  private Jdbi jdbi;
  private JdbiAccessTokenStore store;

  @BeforeEach
  void setUp() {
    jdbi = PostgresFixture.ready();
    PostgresFixture.reset();
    store = new JdbiAccessTokenStore(jdbi);
  }

  @Test
  void recordThenExistsThenDelete() {
    new AccessTokenStoreScenarios(store).recordThenExistsThenDelete();
  }

  @Test
  void existsReturnsFalseForUnknownJti() {
    new AccessTokenStoreScenarios(store).existsReturnsFalseForUnknownJti();
  }

  @Test
  void deleteAllForUserRemovesEveryRow() {
    new AccessTokenStoreScenarios(store).deleteAllForUserRemovesEveryRow();
  }

  @Test
  void deleteExpiredBeforePrunesOnlyExpiredRows() {
    new AccessTokenStoreScenarios(store).deleteExpiredBeforePrunesOnlyExpiredRows();
  }

  @Test
  void recordIsIdempotent() {
    new AccessTokenStoreScenarios(store).recordIsIdempotent();
  }
}
