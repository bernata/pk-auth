// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import org.junit.jupiter.api.Test;

class InMemoryRefreshTokenRepositoryTest {

  @Test
  void issueRotateRevokeHappyPath() {
    new RefreshTokenScenarios(new InMemoryRefreshTokenRepository()).issueRotateRevokeHappyPath();
  }

  @Test
  void rotationUpdatesFamilyChainAndChildLinksToParent() {
    new RefreshTokenScenarios(new InMemoryRefreshTokenRepository())
        .rotationUpdatesFamilyChainAndChildLinksToParent();
  }

  @Test
  void replayOfUsedTokenScorchesEntireFamily() {
    new RefreshTokenScenarios(new InMemoryRefreshTokenRepository())
        .replayOfUsedTokenScorchesEntireFamily();
  }

  @Test
  void expiredTokenRotationReturnsExpired() {
    new RefreshTokenScenarios(new InMemoryRefreshTokenRepository())
        .expiredTokenRotationReturnsExpired();
  }

  @Test
  void unknownRefreshIdReturnsUnknown() {
    new RefreshTokenScenarios(new InMemoryRefreshTokenRepository())
        .unknownRefreshIdReturnsUnknown();
  }

  @Test
  void wrongSecretReturnsUnknownAndDoesNotBurnLegitToken() {
    new RefreshTokenScenarios(new InMemoryRefreshTokenRepository())
        .wrongSecretReturnsUnknownAndDoesNotBurnLegitToken();
  }

  @Test
  void revokeFamilyIsIdempotent() {
    new RefreshTokenScenarios(new InMemoryRefreshTokenRepository()).revokeFamilyIsIdempotent();
  }

  @Test
  void revokeAllForUserRevokesEveryActiveFamily() {
    new RefreshTokenScenarios(new InMemoryRefreshTokenRepository())
        .revokeAllForUserRevokesEveryActiveFamily();
  }

  @Test
  void concurrentRotationExactlyOneSucceedsFamilyRevoked() throws Exception {
    new RefreshTokenScenarios(new InMemoryRefreshTokenRepository())
        .concurrentRotationExactlyOneSucceedsFamilyRevoked();
  }
}
