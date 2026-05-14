// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.admin.AdminResult;
import com.codeheadsystems.pkauth.spring.admin.AdminResultMapper;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

class AdminResultMapperTest {

  @Test
  void successUnwrapsPayload() {
    ResponseEntity<Object> r = AdminResultMapper.toResponse(new AdminResult.Success<>("hello"));
    assertThat(r.getStatusCode().value()).isEqualTo(200);
    assertThat(r.getBody()).isEqualTo("hello");
  }

  @Test
  void notFoundIs404() {
    ResponseEntity<Object> r = AdminResultMapper.toResponse(new AdminResult.NotFound<String>());
    assertThat(r.getStatusCode().value()).isEqualTo(404);
  }

  @Test
  void forbiddenIs403() {
    ResponseEntity<Object> r = AdminResultMapper.toResponse(new AdminResult.Forbidden<String>());
    assertThat(r.getStatusCode().value()).isEqualTo(403);
  }

  @Test
  void validationFailedIs400() {
    ResponseEntity<Object> r =
        AdminResultMapper.toResponse(new AdminResult.ValidationFailed<String>("bad"));
    assertThat(r.getStatusCode().value()).isEqualTo(400);
  }

  @Test
  void conflictIs409() {
    ResponseEntity<Object> r =
        AdminResultMapper.toResponse(new AdminResult.Conflict<String>("nope"));
    assertThat(r.getStatusCode().value()).isEqualTo(409);
  }

  @Test
  void rateLimitedIs429WithRetryAfter() {
    ResponseEntity<Object> r =
        AdminResultMapper.toResponse(new AdminResult.RateLimited<String>(Duration.ofSeconds(30)));
    assertThat(r.getStatusCode().value()).isEqualTo(429);
    assertThat(r.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
  }

  @Test
  void emptyResponseSuccessIs204() {
    ResponseEntity<Object> r = AdminResultMapper.toEmptyResponse(new AdminResult.Success<>(null));
    assertThat(r.getStatusCode().value()).isEqualTo(204);
  }

  @Test
  void emptyResponseNotFoundIs404() {
    ResponseEntity<Object> r = AdminResultMapper.toEmptyResponse(new AdminResult.NotFound<Void>());
    assertThat(r.getStatusCode().value()).isEqualTo(404);
  }

  @Test
  void emptyResponseForbidden() {
    assertThat(
            AdminResultMapper.toEmptyResponse(new AdminResult.Forbidden<Void>())
                .getStatusCode()
                .value())
        .isEqualTo(403);
  }

  @Test
  void emptyResponseValidation() {
    assertThat(
            AdminResultMapper.toEmptyResponse(new AdminResult.ValidationFailed<Void>("bad"))
                .getStatusCode()
                .value())
        .isEqualTo(400);
  }

  @Test
  void emptyResponseConflict() {
    assertThat(
            AdminResultMapper.toEmptyResponse(new AdminResult.Conflict<Void>("nope"))
                .getStatusCode()
                .value())
        .isEqualTo(409);
  }

  @Test
  void emptyResponseRateLimited() {
    ResponseEntity<Object> r =
        AdminResultMapper.toEmptyResponse(
            new AdminResult.RateLimited<Void>(Duration.ofSeconds(15)));
    assertThat(r.getStatusCode().value()).isEqualTo(429);
    assertThat(r.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("15");
  }
}
