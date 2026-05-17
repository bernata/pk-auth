// SPDX-License-Identifier: MIT

/**
 * Shared in-memory rate-limiting helpers. Feature-module rate limiters (backup codes, magic links,
 * ceremony) wrap {@link com.codeheadsystems.pkauth.ratelimit.InMemoryWindowCounter} with their own
 * key-composition rule so they keep distinct SPI signatures while sharing one expiry/storage
 * implementation.
 */
@org.jspecify.annotations.NullMarked
package com.codeheadsystems.pkauth.ratelimit;
