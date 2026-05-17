// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.testkit.RefreshTokenScenarios;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class DynamoDbRefreshTokenRepositoryIntegrationTest {

  private DynamoDbRefreshTokenRepository repository;

  @BeforeEach
  void setUp() {
    DynamoDbClient client = DynamoDbLocalFixture.client();
    DynamoDbEnhancedClient enhanced = DynamoDbLocalFixture.enhanced();
    String suffix = UUID.randomUUID().toString().substring(0, 8);
    PkAuthDynamoTables tables =
        new PkAuthDynamoTables("PkAuthCore_" + suffix, "PkAuthUsers_" + suffix);
    new DynamoDbSchemaBootstrapper(client, tables).bootstrap();
    repository = new DynamoDbRefreshTokenRepository(enhanced, tables);
  }

  @Test
  void issueRotateRevokeHappyPath() {
    new RefreshTokenScenarios(repository).issueRotateRevokeHappyPath();
  }

  @Test
  void rotationUpdatesFamilyChainAndChildLinksToParent() {
    new RefreshTokenScenarios(repository).rotationUpdatesFamilyChainAndChildLinksToParent();
  }

  @Test
  void replayOfUsedTokenScorchesEntireFamily() {
    new RefreshTokenScenarios(repository).replayOfUsedTokenScorchesEntireFamily();
  }

  @Test
  void expiredTokenRotationReturnsExpired() {
    new RefreshTokenScenarios(repository).expiredTokenRotationReturnsExpired();
  }

  @Test
  void unknownRefreshIdReturnsUnknown() {
    new RefreshTokenScenarios(repository).unknownRefreshIdReturnsUnknown();
  }

  @Test
  void wrongSecretReturnsUnknownAndDoesNotBurnLegitToken() {
    new RefreshTokenScenarios(repository).wrongSecretReturnsUnknownAndDoesNotBurnLegitToken();
  }

  @Test
  void revokeFamilyIsIdempotent() {
    new RefreshTokenScenarios(repository).revokeFamilyIsIdempotent();
  }

  @Test
  void revokeAllForUserRevokesEveryActiveFamily() {
    new RefreshTokenScenarios(repository).revokeAllForUserRevokesEveryActiveFamily();
  }

  /** The load-bearing concurrent rotation race test. Must pass against real DynamoDB Local. */
  @Test
  void concurrentRotationExactlyOneSucceedsFamilyRevoked() throws Exception {
    new RefreshTokenScenarios(repository).concurrentRotationExactlyOneSucceedsFamilyRevoked();
  }
}
