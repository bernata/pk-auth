// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import org.junit.jupiter.api.Test;

class InMemoryAccessTokenStoreTest {

  @Test
  void recordThenExistsThenDelete() {
    new AccessTokenStoreScenarios(new InMemoryAccessTokenStore()).recordThenExistsThenDelete();
  }

  @Test
  void existsReturnsFalseForUnknownJti() {
    new AccessTokenStoreScenarios(new InMemoryAccessTokenStore()).existsReturnsFalseForUnknownJti();
  }

  @Test
  void deleteAllForUserRemovesEveryRow() {
    new AccessTokenStoreScenarios(new InMemoryAccessTokenStore()).deleteAllForUserRemovesEveryRow();
  }

  @Test
  void deleteExpiredBeforePrunesOnlyExpiredRows() {
    new AccessTokenStoreScenarios(new InMemoryAccessTokenStore())
        .deleteExpiredBeforePrunesOnlyExpiredRows();
  }

  @Test
  void recordIsIdempotent() {
    new AccessTokenStoreScenarios(new InMemoryAccessTokenStore()).recordIsIdempotent();
  }
}
