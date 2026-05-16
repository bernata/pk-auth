// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import com.codeheadsystems.pkauth.admin.AdminResult.Conflict;
import com.codeheadsystems.pkauth.admin.AdminResult.Forbidden;
import com.codeheadsystems.pkauth.admin.AdminResult.NotFound;
import com.codeheadsystems.pkauth.admin.AdminResult.RateLimited;
import com.codeheadsystems.pkauth.admin.AdminResult.Success;
import com.codeheadsystems.pkauth.admin.AdminResult.ValidationFailed;
import org.jspecify.annotations.Nullable;

/**
 * The wire-format error body that every adapter emits for a non-success {@link AdminResult}. JSON
 * shape is {@code {"error": "code", "detail": "message"?}} — both keys lower-snake-case, {@code
 * detail} present only when the result variant carried one.
 *
 * <p>Codes:
 *
 * <ul>
 *   <li>{@code not_found} — {@link NotFound}
 *   <li>{@code forbidden} — {@link Forbidden}
 *   <li>{@code validation_failed} — {@link ValidationFailed}, with {@code detail}
 *   <li>{@code conflict} — {@link Conflict}, with {@code detail}
 *   <li>{@code rate_limited} — {@link RateLimited}; {@code Retry-After} header carries the wait
 * </ul>
 */
public record AdminErrorBody(String error, @Nullable String detail) {

  /** Builds the matching body for any non-{@link Success} variant, or {@code null} for success. */
  public static @Nullable AdminErrorBody of(AdminResult<?> result) {
    return switch (result) {
      case Success<?> ignored -> null;
      case NotFound<?> ignored -> new AdminErrorBody("not_found", null);
      case Forbidden<?> ignored -> new AdminErrorBody("forbidden", null);
      case ValidationFailed<?> v -> new AdminErrorBody("validation_failed", v.detail());
      case Conflict<?> c -> new AdminErrorBody("conflict", c.detail());
      case RateLimited<?> ignored -> new AdminErrorBody("rate_limited", null);
    };
  }
}
