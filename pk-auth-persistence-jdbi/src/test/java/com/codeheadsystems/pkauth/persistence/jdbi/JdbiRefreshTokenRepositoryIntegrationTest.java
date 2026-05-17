// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.jdbi;

import com.codeheadsystems.pkauth.testkit.RefreshTokenScenarios;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@DisabledIfEnvironmentVariable(named = "PKAUTH_SKIP_TESTCONTAINERS", matches = "1")
class JdbiRefreshTokenRepositoryIntegrationTest {

  private JdbiRefreshTokenRepository repository;

  @BeforeEach
  void setUp() {
    Jdbi jdbi = PostgresFixture.ready();
    PostgresFixture.reset();
    repository = new JdbiRefreshTokenRepository(jdbi);
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

  /** The load-bearing concurrent rotation race test. Must pass against real Postgres. */
  @Test
  void concurrentRotationExactlyOneSucceedsFamilyRevoked() throws Exception {
    new RefreshTokenScenarios(repository).concurrentRotationExactlyOneSucceedsFamilyRevoked();
  }
}
