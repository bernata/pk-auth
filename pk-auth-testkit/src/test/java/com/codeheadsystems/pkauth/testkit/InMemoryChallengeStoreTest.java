// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import org.junit.jupiter.api.Test;

/** Drives the shared {@link ChallengeStoreScenarios} against the in-memory reference store. */
class InMemoryChallengeStoreTest {

  @Test
  void takeOnceConsumesExactlyOnce() {
    new ChallengeStoreScenarios(new InMemoryChallengeStore()).takeOnceConsumesExactlyOnce();
  }

  @Test
  void concurrentTakeOnceYieldsExactlyOneWinner() throws Exception {
    new ChallengeStoreScenarios(new InMemoryChallengeStore())
        .concurrentTakeOnceYieldsExactlyOneWinner();
  }
}
