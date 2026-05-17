// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh.web;

import java.time.Instant;
import java.util.Objects;

/**
 * Successful response from {@code POST /auth/refresh}.
 *
 * @param refreshToken the wire token to use on the next refresh
 * @param accessToken a freshly-minted JWT scoped to the rotated token's audience
 * @param expiresAt absolute expiry of the new refresh token
 * @since 1.1.0
 */
public record RefreshResponse(String refreshToken, String accessToken, Instant expiresAt) {
  public RefreshResponse {
    Objects.requireNonNull(refreshToken, "refreshToken");
    Objects.requireNonNull(accessToken, "accessToken");
    Objects.requireNonNull(expiresAt, "expiresAt");
  }
}
