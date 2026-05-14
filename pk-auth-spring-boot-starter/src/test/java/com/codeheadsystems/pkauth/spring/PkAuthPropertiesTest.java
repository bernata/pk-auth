// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.spring.config.PkAuthProperties;
import java.time.Duration;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PkAuthPropertiesTest {

  @Test
  void blanksFallToDefaults() {
    PkAuthProperties props = new PkAuthProperties(null, null, null);
    assertThat(props.relyingParty().id()).isEqualTo("localhost");
    assertThat(props.jwt().issuer()).isEqualTo("pk-auth");
    assertThat(props.ceremony().challengeTtl()).isEqualTo(Duration.ofMinutes(5));
  }

  @Test
  void preservesExplicitValues() {
    PkAuthProperties props =
        new PkAuthProperties(
            new PkAuthProperties.RelyingParty(
                "example.com", "Example", Set.of("https://example.com")),
            new PkAuthProperties.Jwt(
                "iss", "aud", "secret-that-is-long-enough-32b!!", Duration.ofMinutes(30)),
            new PkAuthProperties.Ceremony(Duration.ofMinutes(2)));
    assertThat(props.relyingParty().id()).isEqualTo("example.com");
    assertThat(props.jwt().tokenTtl()).isEqualTo(Duration.ofMinutes(30));
    assertThat(props.ceremony().challengeTtl()).isEqualTo(Duration.ofMinutes(2));
  }

  @Test
  void componentDefaultsHaveSensibleValues() {
    assertThat(PkAuthProperties.RelyingParty.defaults().origins())
        .containsExactly("http://localhost:8080");
    assertThat(PkAuthProperties.Jwt.defaults().secret()).isNull();
    assertThat(PkAuthProperties.Ceremony.defaults().challengeTtl())
        .isEqualTo(Duration.ofMinutes(5));
  }
}
