// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class JwtSecretResolverTest {

  @Test
  void resolveHs256BytesReturnsUtf8BytesWhenAtLeast32Bytes() {
    String secret = "integration-test-secret-must-be-32-bytes";
    byte[] bytes = JwtSecretResolver.resolveHs256Bytes(secret);
    assertThat(bytes).hasSizeGreaterThanOrEqualTo(32);
  }

  @Test
  void resolveHs256KeysetBuildsKeyset() {
    String secret = "integration-test-secret-must-be-32-bytes";
    JwtKeyset keyset = JwtSecretResolver.resolveHs256Keyset(secret);
    assertThat(keyset).isNotNull();
  }

  @Test
  void resolveHs256BytesRejectsNull() {
    assertThatThrownBy(() -> JwtSecretResolver.resolveHs256Bytes(null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("pkauth.jwt.secret must be configured");
  }

  @Test
  void resolveHs256BytesRejectsBlank() {
    assertThatThrownBy(() -> JwtSecretResolver.resolveHs256Bytes("   "))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("pkauth.jwt.secret must be configured");
  }

  @Test
  void resolveHs256BytesRejectsShortSecret() {
    assertThatThrownBy(() -> JwtSecretResolver.resolveHs256Bytes("too-short"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("at least 32 bytes");
  }
}
