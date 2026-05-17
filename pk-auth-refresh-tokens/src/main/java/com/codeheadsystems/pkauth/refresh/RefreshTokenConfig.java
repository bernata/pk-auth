// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import java.time.Duration;
import java.util.Objects;

/**
 * Configuration for {@link RefreshTokenService}.
 *
 * @param ttlPolicy per-audience refresh TTL dispatch
 * @param secretBytes how many random bytes to generate for each refresh-token secret. Default 32
 *     (256 bits) — high enough that the hash-at-rest is brute-force resistant without salt.
 * @param refreshIdBytes how many random bytes for the {@code refreshId} half of the wire format.
 *     Default 16 (128 bits) — more than enough to identify a row without collision.
 * @param cleanupRetention how long after a row is used or revoked to keep it around for forensic
 *     visibility. Operator-driven cleanup ({@link
 *     com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository#deleteExpiredBefore}) uses this
 *     as the cutoff offset. Default 30 days.
 * @since 1.1.0
 */
public record RefreshTokenConfig(
    RefreshTtlPolicy ttlPolicy, int secretBytes, int refreshIdBytes, Duration cleanupRetention) {

  /** Default secret entropy: 32 bytes (256 bits) from {@code SecureRandom}. */
  public static final int DEFAULT_SECRET_BYTES = 32;

  /** Default refreshId size: 16 bytes (128 bits). */
  public static final int DEFAULT_REFRESH_ID_BYTES = 16;

  /** Default forensic retention for used/revoked rows: 30 days. */
  public static final Duration DEFAULT_CLEANUP_RETENTION = Duration.ofDays(30);

  /** Default refresh-token TTL when {@link RefreshTtlPolicy#single(Duration)} is used: 14 days. */
  public static final Duration DEFAULT_REFRESH_TTL = Duration.ofDays(14);

  public RefreshTokenConfig {
    Objects.requireNonNull(ttlPolicy, "ttlPolicy");
    if (secretBytes < 16) {
      throw new IllegalArgumentException("secretBytes must be >= 16 (got " + secretBytes + ")");
    }
    if (refreshIdBytes < 8) {
      throw new IllegalArgumentException(
          "refreshIdBytes must be >= 8 (got " + refreshIdBytes + ")");
    }
    Objects.requireNonNull(cleanupRetention, "cleanupRetention");
    if (cleanupRetention.isNegative()) {
      throw new IllegalArgumentException("cleanupRetention must be non-negative");
    }
  }

  /** Convenience factory pinning the documented defaults around a single-TTL policy. */
  public static RefreshTokenConfig defaults() {
    return new RefreshTokenConfig(
        RefreshTtlPolicy.single(DEFAULT_REFRESH_TTL),
        DEFAULT_SECRET_BYTES,
        DEFAULT_REFRESH_ID_BYTES,
        DEFAULT_CLEANUP_RETENTION);
  }
}
