// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.admin;

import com.codeheadsystems.pkauth.admin.AdminResult;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

/**
 * Maps a sealed {@link AdminResult} variant to a Spring {@link ResponseEntity}. Centralizing the
 * mapping keeps {@link PkAuthAdminController} short and ensures every endpoint returns the same
 * shape for the same outcome variant — required by brief §6.10 / §6.9 ("Adapters map these to HTTP
 * status codes via a single shared {@code PkAuthAdminResultMapper}"). Non-success bodies use the
 * unified envelope {@code {"outcome": "<code>", "error": "<code>", "detail": "<message>?}} so the
 * wire shape is consistent across ceremony and admin endpoints, and identical across the Spring,
 * Dropwizard, and Micronaut adapters.
 */
public final class PkAuthAdminResultMapper {

  private PkAuthAdminResultMapper() {}

  /** Converts a non-void result. Success returns its payload; non-success maps to an error body. */
  public static <T> ResponseEntity<Object> toResponse(AdminResult<T> result) {
    return switch (result) {
      case AdminResult.Success<T> success -> ResponseEntity.ok(success.value());
      case AdminResult.NotFound<T> nf ->
          ResponseEntity.status(404).body(errorEnvelope("not_found", null));
      case AdminResult.Forbidden<T> f ->
          ResponseEntity.status(403).body(errorEnvelope("forbidden", null));
      case AdminResult.ValidationFailed<T> v ->
          ResponseEntity.badRequest().body(errorEnvelope("validation_failed", v.detail()));
      case AdminResult.Conflict<T> c ->
          ResponseEntity.status(409).body(errorEnvelope("conflict", c.detail()));
      case AdminResult.RateLimited<T> r ->
          ResponseEntity.status(429)
              .header(HttpHeaders.RETRY_AFTER, Long.toString(r.retryAfter().toSeconds()))
              .body(errorEnvelope("rate_limited", null));
    };
  }

  /** Same as {@link #toResponse} but used for void-shaped successes (returns 204 No Content). */
  public static ResponseEntity<Object> toEmptyResponse(AdminResult<Void> result) {
    return switch (result) {
      case AdminResult.Success<Void> success -> ResponseEntity.noContent().build();
      case AdminResult.NotFound<Void> nf ->
          ResponseEntity.status(404).body(errorEnvelope("not_found", null));
      case AdminResult.Forbidden<Void> f ->
          ResponseEntity.status(403).body(errorEnvelope("forbidden", null));
      case AdminResult.ValidationFailed<Void> v ->
          ResponseEntity.badRequest().body(errorEnvelope("validation_failed", v.detail()));
      case AdminResult.Conflict<Void> c ->
          ResponseEntity.status(409).body(errorEnvelope("conflict", c.detail()));
      case AdminResult.RateLimited<Void> r ->
          ResponseEntity.status(429)
              .header(HttpHeaders.RETRY_AFTER, Long.toString(r.retryAfter().toSeconds()))
              .body(errorEnvelope("rate_limited", null));
    };
  }

  /**
   * Builds the unified error envelope: {@code {"outcome": "<code>", "error": "<code>", "detail":
   * "<message>"?}}. Both {@code outcome} and {@code error} carry the same machine-readable tag so
   * clients that key off either field keep working; {@code detail} is omitted when {@code null}.
   */
  static Map<String, Object> errorEnvelope(String code, @Nullable String detail) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("outcome", code);
    body.put("error", code);
    if (detail != null) {
      body.put("detail", detail);
    }
    return body;
  }
}
