// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Locks in the shared admin error-body wire shape so a future-version drift in either adapter is
 * caught here rather than in production traffic.
 */
class AdminErrorBodyTest {

  @Test
  void successYieldsNull() {
    assertThat(AdminErrorBody.of(new AdminResult.Success<>("payload"))).isNull();
  }

  @Test
  void notFound() {
    assertThat(AdminErrorBody.of(new AdminResult.NotFound<String>()))
        .isEqualTo(new AdminErrorBody("not_found", null));
  }

  @Test
  void forbidden() {
    assertThat(AdminErrorBody.of(new AdminResult.Forbidden<String>()))
        .isEqualTo(new AdminErrorBody("forbidden", null));
  }

  @Test
  void validationFailedKeepsDetail() {
    assertThat(AdminErrorBody.of(new AdminResult.ValidationFailed<String>("email must be set")))
        .isEqualTo(new AdminErrorBody("validation_failed", "email must be set"));
  }

  @Test
  void conflictKeepsDetail() {
    assertThat(AdminErrorBody.of(new AdminResult.Conflict<String>("would orphan account")))
        .isEqualTo(new AdminErrorBody("conflict", "would orphan account"));
  }

  @Test
  void rateLimitedHasNoDetailInBody() {
    // The Retry-After header carries the wait time; the body only needs the error code so
    // clients can branch on it.
    assertThat(AdminErrorBody.of(new AdminResult.RateLimited<String>(Duration.ofMinutes(2))))
        .isEqualTo(new AdminErrorBody("rate_limited", null));
  }
}
