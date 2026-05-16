// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.admin;

import com.codeheadsystems.pkauth.admin.AdminErrorBody;
import com.codeheadsystems.pkauth.admin.AdminResult;
import jakarta.ws.rs.core.Response;

/**
 * Maps each {@link AdminResult} variant onto an HTTP response. Centralized so every admin endpoint
 * surfaces the same wire contract — brief §6.9. Non-success bodies are JSON {@link AdminErrorBody}
 * envelopes ({@code {"error": code, "detail": message?}}) to match the Spring and Micronaut
 * adapters byte-for-byte.
 *
 * <p>Status codes:
 *
 * <ul>
 *   <li>{@code Success} → 200 (or 204 when payload is {@code null}/{@code Void}).
 *   <li>{@code NotFound} → 404.
 *   <li>{@code Forbidden} → 403.
 *   <li>{@code ValidationFailed} → 400.
 *   <li>{@code Conflict} → 409.
 *   <li>{@code RateLimited} → 429 with {@code Retry-After} header.
 * </ul>
 */
public final class PkAuthAdminResultMapper {

  private PkAuthAdminResultMapper() {}

  /** Builds a Jersey {@link Response} from {@code result}. */
  public static <T> Response toResponse(AdminResult<T> result) {
    return switch (result) {
      case AdminResult.Success<T> s -> {
        if (s.value() == null) {
          yield Response.noContent().build();
        }
        yield Response.ok(s.value()).build();
      }
      case AdminResult.NotFound<T> n ->
          Response.status(Response.Status.NOT_FOUND).entity(AdminErrorBody.of(result)).build();
      case AdminResult.Forbidden<T> f ->
          Response.status(Response.Status.FORBIDDEN).entity(AdminErrorBody.of(result)).build();
      case AdminResult.ValidationFailed<T> v ->
          Response.status(Response.Status.BAD_REQUEST).entity(AdminErrorBody.of(result)).build();
      case AdminResult.Conflict<T> c ->
          Response.status(Response.Status.CONFLICT).entity(AdminErrorBody.of(result)).build();
      case AdminResult.RateLimited<T> rl ->
          Response.status(429)
              .header("Retry-After", Long.toString(Math.max(1, rl.retryAfter().toSeconds())))
              .entity(AdminErrorBody.of(result))
              .build();
    };
  }
}
