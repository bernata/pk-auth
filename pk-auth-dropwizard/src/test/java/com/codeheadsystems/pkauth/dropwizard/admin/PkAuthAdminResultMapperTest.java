// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.admin.AdminResult;
import jakarta.ws.rs.core.Response;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class PkAuthAdminResultMapperTest {

  @Test
  void successWithValueIs200() {
    Response r = PkAuthAdminResultMapper.toResponse(new AdminResult.Success<>("hello"));
    assertThat(r.getStatus()).isEqualTo(200);
    assertThat(r.getEntity()).isEqualTo("hello");
  }

  @Test
  void successWithNullIs204() {
    Response r = PkAuthAdminResultMapper.toResponse(new AdminResult.Success<Void>(null));
    assertThat(r.getStatus()).isEqualTo(204);
  }

  @Test
  void notFoundIs404() {
    Response r = PkAuthAdminResultMapper.toResponse(new AdminResult.NotFound<>());
    assertThat(r.getStatus()).isEqualTo(404);
  }

  @Test
  void forbiddenIs403() {
    Response r = PkAuthAdminResultMapper.toResponse(new AdminResult.Forbidden<>());
    assertThat(r.getStatus()).isEqualTo(403);
  }

  @Test
  @SuppressWarnings("unchecked")
  void validationFailedIs400WithUnifiedEnvelope() {
    Response r =
        PkAuthAdminResultMapper.toResponse(new AdminResult.ValidationFailed<>("bad input"));
    assertThat(r.getStatus()).isEqualTo(400);
    Map<String, Object> body = (Map<String, Object>) r.getEntity();
    assertThat(body).containsEntry("outcome", "validation_failed");
    assertThat(body).containsEntry("error", "validation_failed");
    assertThat(body).containsEntry("detail", "bad input");
  }

  @Test
  @SuppressWarnings("unchecked")
  void conflictIs409WithUnifiedEnvelope() {
    Response r =
        PkAuthAdminResultMapper.toResponse(new AdminResult.Conflict<>("invariant violation"));
    assertThat(r.getStatus()).isEqualTo(409);
    Map<String, Object> body = (Map<String, Object>) r.getEntity();
    assertThat(body).containsEntry("outcome", "conflict");
    assertThat(body).containsEntry("error", "conflict");
    assertThat(body).containsEntry("detail", "invariant violation");
  }

  @Test
  @SuppressWarnings("unchecked")
  void notFoundCarriesUnifiedEnvelope() {
    Response r = PkAuthAdminResultMapper.toResponse(new AdminResult.NotFound<>());
    Map<String, Object> body = (Map<String, Object>) r.getEntity();
    assertThat(body).containsEntry("outcome", "not_found");
    assertThat(body).containsEntry("error", "not_found");
    assertThat(body).doesNotContainKey("detail");
  }

  @Test
  @SuppressWarnings("unchecked")
  void forbiddenCarriesUnifiedEnvelope() {
    Response r = PkAuthAdminResultMapper.toResponse(new AdminResult.Forbidden<>());
    Map<String, Object> body = (Map<String, Object>) r.getEntity();
    assertThat(body).containsEntry("outcome", "forbidden");
    assertThat(body).containsEntry("error", "forbidden");
    assertThat(body).doesNotContainKey("detail");
  }

  @Test
  void rateLimitedIs429WithRetryAfterHeader() {
    Response r =
        PkAuthAdminResultMapper.toResponse(new AdminResult.RateLimited<>(Duration.ofMinutes(2)));
    assertThat(r.getStatus()).isEqualTo(429);
    assertThat(r.getHeaderString("Retry-After")).isEqualTo("120");
  }

  @Test
  void rateLimitedFloorsRetryAfterAtOneSecond() {
    Response r = PkAuthAdminResultMapper.toResponse(new AdminResult.RateLimited<>(Duration.ZERO));
    assertThat(r.getHeaderString("Retry-After")).isEqualTo("1");
  }
}
