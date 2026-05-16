// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.credential.CredentialMetadata;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * Wire-shape projection of a credential for the credential-management endpoints. Mirrors {@link
 * CredentialMetadata} but lives in the admin module so the wire schema is owned here.
 *
 * <p>The {@code credentialId} field is a raw byte array (not a {@code CredentialId}) because this
 * record is serialized directly to JSON as the wire shape — Jackson converts {@code byte[]} to
 * base64 transparently, which matches the published HTTP contract. The internal SPI types use the
 * type-safe {@code CredentialId} value class instead.
 */
public record CredentialSummary(
    byte[] credentialId,
    String label,
    @Nullable UUID aaguid,
    Set<String> transports,
    boolean backupEligible,
    boolean backupState,
    Instant createdAt,
    @Nullable Instant lastUsedAt) {

  public CredentialSummary {
    Objects.requireNonNull(credentialId, "credentialId");
    Objects.requireNonNull(label, "label");
    Objects.requireNonNull(transports, "transports");
    Objects.requireNonNull(createdAt, "createdAt");
    credentialId = credentialId.clone();
    transports = Set.copyOf(transports);
  }

  @Override
  public byte[] credentialId() {
    return credentialId.clone();
  }

  /** Builds a summary from a stored {@link CredentialRecord}. */
  public static CredentialSummary of(CredentialRecord r) {
    Set<String> wireTransports = new LinkedHashSet<>();
    for (Transport t : r.transports()) {
      wireTransports.add(t.wireName());
    }
    return new CredentialSummary(
        r.credentialId().value(),
        r.label(),
        r.aaguid(),
        wireTransports,
        r.backupEligible(),
        r.backupState(),
        r.createdAt(),
        r.lastUsedAt());
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof CredentialSummary other
        && Arrays.equals(this.credentialId, other.credentialId)
        && this.label.equals(other.label)
        && Objects.equals(this.aaguid, other.aaguid)
        && this.transports.equals(other.transports)
        && this.backupEligible == other.backupEligible
        && this.backupState == other.backupState
        && this.createdAt.equals(other.createdAt)
        && Objects.equals(this.lastUsedAt, other.lastUsedAt);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        Arrays.hashCode(credentialId),
        label,
        aaguid,
        transports,
        backupEligible,
        backupState,
        createdAt,
        lastUsedAt);
  }

  @Override
  public String toString() {
    return "CredentialSummary[credentialId="
        + HexFormat.of().formatHex(credentialId)
        + ", label="
        + label
        + ", aaguid="
        + aaguid
        + "]";
  }
}
