// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Set;
import org.junit.jupiter.api.Test;

final class PkAuthConfigTest {

  @Test
  void relyingPartyDefensivelyCopiesOrigins() {
    Set<String> origins = new java.util.HashSet<>(Set.of("https://example.com"));
    PkAuthConfig.RelyingParty rp = new PkAuthConfig.RelyingParty("example.com", "Example", origins);
    origins.clear();
    assertThat(rp.origins()).containsExactly("https://example.com");
  }

  @Test
  void relyingPartyRejectsEmptyOrigins() {
    assertThatThrownBy(() -> new PkAuthConfig.RelyingParty("example.com", "Example", Set.of()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("at least one origin");
  }

  @Test
  void jwtRejectsShortSecret() {
    assertThatThrownBy(() -> new PkAuthConfig.Jwt("iss", "aud", new byte[16], null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("32 bytes");
  }

  @Test
  void jwtSecretIsDefensivelyCopied() {
    byte[] secret = new byte[32];
    secret[0] = 1;
    PkAuthConfig.Jwt jwt = new PkAuthConfig.Jwt("iss", "aud", secret, null);
    secret[0] = 99;
    assertThat(jwt.secret()[0]).isEqualTo((byte) 1);
  }

  @Test
  void ceremonyDefaultsToNullTtl() {
    PkAuthConfig.Ceremony c = new PkAuthConfig.Ceremony();
    assertThat(c.challengeTtl()).isNull();
  }

  @Test
  void configRequiresEveryBlock() {
    assertThatThrownBy(() -> new PkAuthConfig(null, null, null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void otpRejectsShortPepper() {
    assertThatThrownBy(() -> new PkAuthConfig.Otp(new byte[8]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("16 bytes");
  }

  @Test
  void otpPepperIsDefensivelyCopied() {
    byte[] pepper = new byte[16];
    pepper[0] = 1;
    PkAuthConfig.Otp otp = new PkAuthConfig.Otp(pepper);
    pepper[0] = 99;
    assertThat(otp.pepper()[0]).isEqualTo((byte) 1);
  }

  @Test
  void magicLinkRequiresNonBlankBaseUrl() {
    assertThatThrownBy(() -> new PkAuthConfig.MagicLink(""))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("non-blank");
    assertThatThrownBy(() -> new PkAuthConfig.MagicLink(null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void legacyThreeArgConstructorLeavesAltFlowBlocksNull() {
    PkAuthConfig cfg =
        new PkAuthConfig(
            new PkAuthConfig.RelyingParty("example.com", "Example", Set.of("https://example.com")),
            new PkAuthConfig.Jwt("iss", "aud", new byte[32], null),
            new PkAuthConfig.Ceremony());
    assertThat(cfg.otp()).isNull();
    assertThat(cfg.magicLink()).isNull();
    assertThat(cfg.backupCode()).isNull();
  }
}
