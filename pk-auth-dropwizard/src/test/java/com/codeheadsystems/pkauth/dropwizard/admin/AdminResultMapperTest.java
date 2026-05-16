// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.admin.AdminErrorBody;
import com.codeheadsystems.pkauth.admin.AdminResult;
import jakarta.ws.rs.core.Response;
import java.time.Duration;
import org.junit.jupiter.api.Test;

final class AdminResultMapperTest {

  @Test
  void successWithValueIs200() {
    Response r = AdminResultMapper.toResponse(new AdminResult.Success<>("hello"));
    assertThat(r.getStatus()).isEqualTo(200);
    assertThat(r.getEntity()).isEqualTo("hello");
  }

  @Test
  void successWithNullIs204() {
    Response r = AdminResultMapper.toResponse(new AdminResult.Success<Void>(null));
    assertThat(r.getStatus()).isEqualTo(204);
  }

  @Test
  void notFoundIs404() {
    Response r = AdminResultMapper.toResponse(new AdminResult.NotFound<>());
    assertThat(r.getStatus()).isEqualTo(404);
  }

  @Test
  void forbiddenIs403() {
    Response r = AdminResultMapper.toResponse(new AdminResult.Forbidden<>());
    assertThat(r.getStatus()).isEqualTo(403);
  }

  @Test
  void validationFailedIs400WithSharedErrorBody() {
    Response r = AdminResultMapper.toResponse(new AdminResult.ValidationFailed<>("bad input"));
    assertThat(r.getStatus()).isEqualTo(400);
    assertThat(r.getEntity()).isEqualTo(new AdminErrorBody("validation_failed", "bad input"));
  }

  @Test
  void conflictIs409WithSharedErrorBody() {
    Response r = AdminResultMapper.toResponse(new AdminResult.Conflict<>("invariant violation"));
    assertThat(r.getStatus()).isEqualTo(409);
    assertThat(r.getEntity()).isEqualTo(new AdminErrorBody("conflict", "invariant violation"));
  }

  @Test
  void notFoundCarriesSharedErrorBody() {
    Response r = AdminResultMapper.toResponse(new AdminResult.NotFound<>());
    assertThat(r.getEntity()).isEqualTo(new AdminErrorBody("not_found", null));
  }

  @Test
  void forbiddenCarriesSharedErrorBody() {
    Response r = AdminResultMapper.toResponse(new AdminResult.Forbidden<>());
    assertThat(r.getEntity()).isEqualTo(new AdminErrorBody("forbidden", null));
  }

  @Test
  void rateLimitedIs429WithRetryAfterHeader() {
    Response r = AdminResultMapper.toResponse(new AdminResult.RateLimited<>(Duration.ofMinutes(2)));
    assertThat(r.getStatus()).isEqualTo(429);
    assertThat(r.getHeaderString("Retry-After")).isEqualTo("120");
  }

  @Test
  void rateLimitedFloorsRetryAfterAtOneSecond() {
    Response r = AdminResultMapper.toResponse(new AdminResult.RateLimited<>(Duration.ZERO));
    assertThat(r.getHeaderString("Retry-After")).isEqualTo("1");
  }
}
