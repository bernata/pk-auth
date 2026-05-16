// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CredentialRecordTest {

  private CredentialRecord build() {
    return new CredentialRecord(
        CredentialId.of(new byte[] {1, 2}),
        UserHandle.of(new byte[] {9}),
        new byte[] {3, 4},
        7L,
        "Yubikey",
        UUID.fromString("00000000-0000-0000-0000-000000000001"),
        Set.of(Transport.USB, Transport.NFC),
        true,
        false,
        Instant.parse("2024-01-01T00:00:00Z"),
        Instant.parse("2024-02-01T00:00:00Z"));
  }

  @Test
  void defensiveCopies() {
    byte[] pubKey = {4, 5, 6};
    CredentialRecord cred =
        new CredentialRecord(
            CredentialId.of(new byte[] {1, 2, 3}),
            UserHandle.random(),
            pubKey,
            0L,
            "x",
            null,
            Set.of(),
            false,
            false,
            Instant.now(),
            null);
    pubKey[0] = 99;
    // CredentialId's value() also returns a defensive copy.
    byte[] credIdValue = cred.credentialId().value();
    credIdValue[0] = 99;
    assertThat(cred.credentialId().value()[0]).isEqualTo((byte) 1);
    assertThat(cred.publicKeyCose()[0]).isEqualTo((byte) 4);
  }

  @Test
  void equalsHashCodeAndToString() {
    CredentialRecord a = build();
    CredentialRecord b = build();
    assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    assertThat(a.toString()).contains("Yubikey").contains("b64url=");
    assertThat(a).isNotEqualTo("nope");
  }

  @Test
  void toMetadataDropsPublicKey() {
    CredentialMetadata meta = build().toMetadata();
    assertThat(meta.label()).isEqualTo("Yubikey");
    assertThat(meta.transports()).containsExactlyInAnyOrder(Transport.USB, Transport.NFC);
    assertThat(meta).isEqualTo(build().toMetadata()).hasSameHashCodeAs(build().toMetadata());
    assertThat(meta.toString()).contains("Yubikey");
  }

  @Test
  void rejectsInvalidArgs() {
    // Empty credential-id bytes are rejected by CredentialId itself.
    assertThatThrownBy(() -> CredentialId.of(new byte[0]))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                new CredentialRecord(
                    CredentialId.of(new byte[] {1}),
                    UserHandle.random(),
                    new byte[0],
                    0L,
                    "x",
                    null,
                    Set.of(),
                    false,
                    false,
                    Instant.now(),
                    null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                new CredentialRecord(
                    CredentialId.of(new byte[] {1}),
                    UserHandle.random(),
                    new byte[] {1},
                    -1L,
                    "x",
                    null,
                    Set.of(),
                    false,
                    false,
                    Instant.now(),
                    null))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
