// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.admin.AdminResponseMapper.AdminResponse;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AdminResponseMapperTest {

  @Test
  void successWithValueIs200() {
    AdminResponse r = AdminResponseMapper.toResponse(new AdminResult.Success<>("hello"));
    assertThat(r.status()).isEqualTo(200);
    assertThat(r.body()).isEqualTo("hello");
    assertThat(r.headers()).isEmpty();
  }

  @Test
  void successWithNullIs204() {
    AdminResponse r = AdminResponseMapper.toResponse(new AdminResult.Success<>(null));
    assertThat(r.status()).isEqualTo(204);
    assertThat(r.body()).isNull();
  }

  @Test
  @SuppressWarnings("unchecked")
  void notFoundCarriesUnifiedEnvelope() {
    AdminResponse r = AdminResponseMapper.toResponse(new AdminResult.NotFound<>());
    assertThat(r.status()).isEqualTo(404);
    Map<String, Object> body = (Map<String, Object>) r.body();
    assertThat(body).containsEntry("outcome", "not_found").containsEntry("error", "not_found");
    assertThat(body).doesNotContainKey("detail");
  }

  @Test
  @SuppressWarnings("unchecked")
  void forbiddenCarriesUnifiedEnvelope() {
    AdminResponse r = AdminResponseMapper.toResponse(new AdminResult.Forbidden<>());
    assertThat(r.status()).isEqualTo(403);
    Map<String, Object> body = (Map<String, Object>) r.body();
    assertThat(body).containsEntry("outcome", "forbidden").containsEntry("error", "forbidden");
  }

  @Test
  @SuppressWarnings("unchecked")
  void validationFailedCarriesDetail() {
    AdminResponse r =
        AdminResponseMapper.toResponse(new AdminResult.ValidationFailed<>("bad input"));
    assertThat(r.status()).isEqualTo(400);
    Map<String, Object> body = (Map<String, Object>) r.body();
    assertThat(body)
        .containsEntry("outcome", "validation_failed")
        .containsEntry("error", "validation_failed")
        .containsEntry("detail", "bad input");
  }

  @Test
  @SuppressWarnings("unchecked")
  void conflictCarriesDetail() {
    AdminResponse r = AdminResponseMapper.toResponse(new AdminResult.Conflict<>("invariant"));
    assertThat(r.status()).isEqualTo(409);
    Map<String, Object> body = (Map<String, Object>) r.body();
    assertThat(body)
        .containsEntry("outcome", "conflict")
        .containsEntry("error", "conflict")
        .containsEntry("detail", "invariant");
  }

  @Test
  void rateLimitedCarriesRetryAfterHeader() {
    AdminResponse r =
        AdminResponseMapper.toResponse(new AdminResult.RateLimited<>(Duration.ofMinutes(2)));
    assertThat(r.status()).isEqualTo(429);
    assertThat(r.headers()).containsEntry("Retry-After", "120");
  }

  @Test
  void rateLimitedFloorsRetryAfterAtOneSecond() {
    AdminResponse r = AdminResponseMapper.toResponse(new AdminResult.RateLimited<>(Duration.ZERO));
    assertThat(r.headers()).containsEntry("Retry-After", "1");
  }

  @Test
  void successMapperWrapsValue() {
    AdminResponse r =
        AdminResponseMapper.toResponse(new AdminResult.Success<>(42), v -> "wrapped:" + v);
    assertThat(r.status()).isEqualTo(200);
    assertThat(r.body()).isEqualTo("wrapped:42");
  }

  @Test
  void successMapperReturningNullProduces204() {
    AdminResponse r = AdminResponseMapper.toResponse(new AdminResult.Success<>("x"), v -> null);
    assertThat(r.status()).isEqualTo(204);
    assertThat(r.body()).isNull();
  }

  @Test
  void successMapperBypassedForNonSuccess() {
    AdminResponse r =
        AdminResponseMapper.toResponse(new AdminResult.NotFound<Integer>(), Object::toString);
    assertThat(r.status()).isEqualTo(404);
  }

  @Test
  void successMapperRejectsNull() {
    assertThatThrownBy(() -> AdminResponseMapper.toResponse(new AdminResult.Success<>("x"), null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void errorEnvelopeOmitsDetailWhenNull() {
    Map<String, Object> body = AdminResponseMapper.errorEnvelope("foo", null);
    assertThat(body).containsEntry("outcome", "foo").containsEntry("error", "foo");
    assertThat(body).doesNotContainKey("detail");
  }
}
