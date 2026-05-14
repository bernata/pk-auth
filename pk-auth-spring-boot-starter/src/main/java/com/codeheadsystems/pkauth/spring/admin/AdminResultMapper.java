// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.admin;

import com.codeheadsystems.pkauth.admin.AdminResult;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

/**
 * Maps a sealed {@link AdminResult} variant to a Spring {@link ResponseEntity}. Centralizing the
 * mapping keeps {@link AdminController} short and ensures every endpoint returns the same shape for
 * the same outcome variant — required by brief §6.10 / §6.9 ("Adapters map these to HTTP status
 * codes via a single shared {@code AdminResultMapper}").
 */
public final class AdminResultMapper {

  private AdminResultMapper() {}

  /** Converts a non-void result. Success returns its payload; non-success maps to an error body. */
  public static <T> ResponseEntity<Object> toResponse(AdminResult<T> result) {
    return switch (result) {
      case AdminResult.Success<T> success -> ResponseEntity.ok(success.value());
      case AdminResult.NotFound<T> nf -> ResponseEntity.status(404).body(error("not_found"));
      case AdminResult.Forbidden<T> f -> ResponseEntity.status(403).body(error("forbidden"));
      case AdminResult.ValidationFailed<T> v ->
          ResponseEntity.badRequest().body(error("validation_failed", v.detail()));
      case AdminResult.Conflict<T> c ->
          ResponseEntity.status(409).body(error("conflict", c.detail()));
      case AdminResult.RateLimited<T> r ->
          ResponseEntity.status(429)
              .header(HttpHeaders.RETRY_AFTER, Long.toString(r.retryAfter().toSeconds()))
              .body(error("rate_limited"));
    };
  }

  /** Same as {@link #toResponse} but used for void-shaped successes (returns 204 No Content). */
  public static ResponseEntity<Object> toEmptyResponse(AdminResult<Void> result) {
    return switch (result) {
      case AdminResult.Success<Void> success -> ResponseEntity.noContent().build();
      case AdminResult.NotFound<Void> nf -> ResponseEntity.status(404).body(error("not_found"));
      case AdminResult.Forbidden<Void> f -> ResponseEntity.status(403).body(error("forbidden"));
      case AdminResult.ValidationFailed<Void> v ->
          ResponseEntity.badRequest().body(error("validation_failed", v.detail()));
      case AdminResult.Conflict<Void> c ->
          ResponseEntity.status(409).body(error("conflict", c.detail()));
      case AdminResult.RateLimited<Void> r ->
          ResponseEntity.status(429)
              .header(HttpHeaders.RETRY_AFTER, Long.toString(r.retryAfter().toSeconds()))
              .body(error("rate_limited"));
    };
  }

  private static Map<String, String> error(String code) {
    return Map.of("error", code);
  }

  private static Map<String, String> error(String code, String detail) {
    return Map.of("error", code, "detail", detail);
  }
}
