// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.testkit.AccessTokenStoreScenarios;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class DynamoDbAccessTokenStoreIntegrationTest {

  private DynamoDbAccessTokenStore store;

  @BeforeEach
  void setUp() {
    DynamoDbClient client = DynamoDbLocalFixture.client();
    DynamoDbEnhancedClient enhanced = DynamoDbLocalFixture.enhanced();
    String suffix = UUID.randomUUID().toString().substring(0, 8);
    PkAuthDynamoTables tables =
        new PkAuthDynamoTables("PkAuthCore_" + suffix, "PkAuthUsers_" + suffix);
    new DynamoDbSchemaBootstrapper(client, tables).bootstrap();
    store = new DynamoDbAccessTokenStore(enhanced, tables);
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

  @Test
  void deleteRejectsForeignOwner() {
    new AccessTokenStoreScenarios(store).deleteRejectsForeignOwner();
  }
}
