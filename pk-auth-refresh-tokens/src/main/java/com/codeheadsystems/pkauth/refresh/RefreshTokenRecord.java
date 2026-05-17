// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.refresh;

import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Persisted shape of a single refresh-token row. The user-facing wire format is {@code
 * "{refreshId}.{secret}"}; only {@link #tokenHash()} (SHA-256 of the raw secret bytes) is stored
 * server-side.
 *
 * <p>Family model: every chain of rotations shares a {@code familyId} (the {@code refreshId} of the
 * family root). Replaying a used token in any family member scorches the entire family.
 *
 * @param refreshId opaque identifier (16 random bytes, base64url-encoded — 22 chars)
 * @param tokenHash SHA-256 of the raw 32-byte secret
 * @param userHandle owning user
 * @param audience the audience this refresh is scoped to (drives per-audience TTL via {@link
 *     RefreshTtlPolicy})
 * @param deviceId optional device identifier; reserved for future device-binding work
 * @param familyId identifier shared by every token in the rotation chain (equals the root's {@code
 *     refreshId})
 * @param parentRefreshId for rotated tokens, the {@code refreshId} of the parent in the chain; null
 *     for the family root
 * @param issuedAt when this token was issued
 * @param expiresAt when this token expires (absolute)
 * @param usedAt set when the atomic rotate primitive transitions this row from fresh to used — the
 *     load-bearing field for replay defense
 * @param revokedAt set when this token (or its family) is revoked
 * @param revokedReason categorical reason matching {@link #revokedAt}; present iff {@code
 *     revokedAt} is set
 * @since 1.1.0
 */
public record RefreshTokenRecord(
    String refreshId,
    byte[] tokenHash,
    UserHandle userHandle,
    String audience,
    Optional<String> deviceId,
    String familyId,
    Optional<String> parentRefreshId,
    Instant issuedAt,
    Instant expiresAt,
    Optional<Instant> usedAt,
    Optional<Instant> revokedAt,
    Optional<RevokeReason> revokedReason) {

  public RefreshTokenRecord {
    Objects.requireNonNull(refreshId, "refreshId");
    if (refreshId.isBlank()) {
      throw new IllegalArgumentException("refreshId must be non-blank");
    }
    Objects.requireNonNull(tokenHash, "tokenHash");
    if (tokenHash.length == 0) {
      throw new IllegalArgumentException("tokenHash must be non-empty");
    }
    Objects.requireNonNull(userHandle, "userHandle");
    Objects.requireNonNull(audience, "audience");
    if (audience.isBlank()) {
      throw new IllegalArgumentException("audience must be non-blank");
    }
    Objects.requireNonNull(deviceId, "deviceId");
    Objects.requireNonNull(familyId, "familyId");
    if (familyId.isBlank()) {
      throw new IllegalArgumentException("familyId must be non-blank");
    }
    Objects.requireNonNull(parentRefreshId, "parentRefreshId");
    Objects.requireNonNull(issuedAt, "issuedAt");
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(usedAt, "usedAt");
    Objects.requireNonNull(revokedAt, "revokedAt");
    Objects.requireNonNull(revokedReason, "revokedReason");
    if (revokedAt.isPresent() != revokedReason.isPresent()) {
      throw new IllegalArgumentException(
          "revokedAt and revokedReason must both be set or both absent");
    }
    tokenHash = tokenHash.clone();
  }

  /** Returns a defensive copy of the stored SHA-256 hash. */
  @Override
  public byte[] tokenHash() {
    return tokenHash.clone();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof RefreshTokenRecord r
        && Objects.equals(refreshId, r.refreshId)
        && Arrays.equals(tokenHash, r.tokenHash)
        && Objects.equals(userHandle, r.userHandle)
        && Objects.equals(audience, r.audience)
        && Objects.equals(deviceId, r.deviceId)
        && Objects.equals(familyId, r.familyId)
        && Objects.equals(parentRefreshId, r.parentRefreshId)
        && Objects.equals(issuedAt, r.issuedAt)
        && Objects.equals(expiresAt, r.expiresAt)
        && Objects.equals(usedAt, r.usedAt)
        && Objects.equals(revokedAt, r.revokedAt)
        && Objects.equals(revokedReason, r.revokedReason);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        refreshId,
        Arrays.hashCode(tokenHash),
        userHandle,
        audience,
        deviceId,
        familyId,
        parentRefreshId,
        issuedAt,
        expiresAt,
        usedAt,
        revokedAt,
        revokedReason);
  }
}
