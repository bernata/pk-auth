// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * Compact-constructor validation for the sealed ceremony result variants. Accessor read-backs and
 * exhaustive-switch coverage are exercised by the ceremony service tests that actually produce
 * these results; only the hand-written validation guards are tested here.
 */
class ResultTypesTest {

  @Test
  void registrationResultInvalidChallengeRejectsNullDetail() {
    assertThatThrownBy(() -> new RegistrationResult.InvalidChallenge(null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void assertionResultSuccessRejectsNegativeSignCount() {
    assertThatThrownBy(
            () ->
                new AssertionResult.Success(
                    UserHandle.random(),
                    CredentialId.of(new byte[] {0}),
                    -1,
                    AssertionResult.CounterStatus.OK))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
