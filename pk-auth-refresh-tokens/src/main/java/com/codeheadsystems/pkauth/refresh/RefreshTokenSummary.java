// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Listing projection for admin / UI surfaces. Carries the metadata needed to render a "your active
 * sessions" view without exposing any secret-bearing fields. Read-only; produced by {@link
 * RefreshTokenService#listForUser(com.codeheadsystems.pkauth.api.UserHandle)}.
 *
 * @param refreshId opaque identifier (no hash, no secret)
 * @param audience scope this refresh covers
 * @param familyId rotation chain identifier; multiple summaries can share a familyId (every row in
 *     the chain has its own listing)
 * @param deviceId optional device identifier
 * @param issuedAt when this row was issued
 * @param expiresAt absolute expiry
 * @param usedAt set if a successor has rotated past this row
 * @param revokedAt set if this row (or its family) is revoked
 * @since 1.1.0
 */
public record RefreshTokenSummary(
    String refreshId,
    String audience,
    String familyId,
    Optional<String> deviceId,
    Instant issuedAt,
    Instant expiresAt,
    Optional<Instant> usedAt,
    Optional<Instant> revokedAt) {

  public RefreshTokenSummary {
    Objects.requireNonNull(refreshId, "refreshId");
    Objects.requireNonNull(audience, "audience");
    Objects.requireNonNull(familyId, "familyId");
    Objects.requireNonNull(deviceId, "deviceId");
    Objects.requireNonNull(issuedAt, "issuedAt");
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(usedAt, "usedAt");
    Objects.requireNonNull(revokedAt, "revokedAt");
  }

  /** Builds the summary from a full record (drops hash + parent linkage). */
  public static RefreshTokenSummary from(RefreshTokenRecord record) {
    Objects.requireNonNull(record, "record");
    return new RefreshTokenSummary(
        record.refreshId(),
        record.audience(),
        record.familyId(),
        record.deviceId(),
        record.issuedAt(),
        record.expiresAt(),
        record.usedAt(),
        record.revokedAt());
  }
}
