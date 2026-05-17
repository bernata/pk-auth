// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh.web;

import org.jspecify.annotations.Nullable;

/**
 * HTTP request body for the {@code POST /auth/refresh} endpoint shared by every adapter.
 *
 * @param refreshToken the wire token last issued to the client (format {@code
 *     "{refreshId}.{secret}"})
 * @since 1.1.0
 */
public record RefreshRequest(@Nullable String refreshToken) {}
