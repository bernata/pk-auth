// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh.web;

import org.jspecify.annotations.Nullable;

/**
 * Body for {@code 401 Unauthorized} responses from {@code POST /auth/refresh}. The {@code detail}
 * field is the canonical machine-readable outcome name ({@code "expired"}, {@code "unknown"},
 * {@code "replayed"}, {@code "revoked"}); {@code reason} carries the categorical revoke reason when
 * {@code detail = "revoked"} ({@code "LOGOUT"}, {@code "USER_DELETED"}, etc.).
 *
 * @since 1.1.0
 */
public record RefreshErrorResponse(String detail, @Nullable String reason) {}
