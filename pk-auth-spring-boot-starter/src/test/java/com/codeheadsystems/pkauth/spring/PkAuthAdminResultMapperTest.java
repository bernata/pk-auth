// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.admin.AdminResult;
import com.codeheadsystems.pkauth.spring.admin.PkAuthAdminResultMapper;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

class PkAuthAdminResultMapperTest {

  @Test
  void successUnwrapsPayload() {
    ResponseEntity<Object> r =
        PkAuthAdminResultMapper.toResponse(new AdminResult.Success<>("hello"));
    assertThat(r.getStatusCode().value()).isEqualTo(200);
    assertThat(r.getBody()).isEqualTo("hello");
  }

  @Test
  void notFoundIs404() {
    ResponseEntity<Object> r =
        PkAuthAdminResultMapper.toResponse(new AdminResult.NotFound<String>());
    assertThat(r.getStatusCode().value()).isEqualTo(404);
  }

  @Test
  void forbiddenIs403() {
    ResponseEntity<Object> r =
        PkAuthAdminResultMapper.toResponse(new AdminResult.Forbidden<String>());
    assertThat(r.getStatusCode().value()).isEqualTo(403);
  }

  @Test
  void validationFailedIs400() {
    ResponseEntity<Object> r =
        PkAuthAdminResultMapper.toResponse(new AdminResult.ValidationFailed<String>("bad"));
    assertThat(r.getStatusCode().value()).isEqualTo(400);
  }

  @Test
  void conflictIs409() {
    ResponseEntity<Object> r =
        PkAuthAdminResultMapper.toResponse(new AdminResult.Conflict<String>("nope"));
    assertThat(r.getStatusCode().value()).isEqualTo(409);
  }

  @Test
  void rateLimitedIs429WithRetryAfter() {
    ResponseEntity<Object> r =
        PkAuthAdminResultMapper.toResponse(
            new AdminResult.RateLimited<String>(Duration.ofSeconds(30)));
    assertThat(r.getStatusCode().value()).isEqualTo(429);
    assertThat(r.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
  }

  /** Unified method auto-detects null payload and returns 204 No Content. */
  @Test
  void nullPayloadSuccessIs204() {
    ResponseEntity<Object> r = PkAuthAdminResultMapper.toResponse(new AdminResult.Success<>(null));
    assertThat(r.getStatusCode().value()).isEqualTo(204);
  }

  @Test
  void voidSuccessNotFoundIs404() {
    ResponseEntity<Object> r = PkAuthAdminResultMapper.toResponse(new AdminResult.NotFound<Void>());
    assertThat(r.getStatusCode().value()).isEqualTo(404);
  }

  @Test
  void voidSuccessForbiddenIs403() {
    assertThat(
            PkAuthAdminResultMapper.toResponse(new AdminResult.Forbidden<Void>())
                .getStatusCode()
                .value())
        .isEqualTo(403);
  }

  @Test
  void voidSuccessValidationFailedIs400() {
    assertThat(
            PkAuthAdminResultMapper.toResponse(new AdminResult.ValidationFailed<Void>("bad"))
                .getStatusCode()
                .value())
        .isEqualTo(400);
  }

  @Test
  void voidSuccessConflictIs409() {
    assertThat(
            PkAuthAdminResultMapper.toResponse(new AdminResult.Conflict<Void>("nope"))
                .getStatusCode()
                .value())
        .isEqualTo(409);
  }

  @Test
  void voidSuccessRateLimitedIs429() {
    ResponseEntity<Object> r =
        PkAuthAdminResultMapper.toResponse(
            new AdminResult.RateLimited<Void>(Duration.ofSeconds(15)));
    assertThat(r.getStatusCode().value()).isEqualTo(429);
    assertThat(r.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("15");
  }
}
