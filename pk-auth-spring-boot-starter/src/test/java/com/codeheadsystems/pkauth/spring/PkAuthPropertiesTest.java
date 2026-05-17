// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.spring.config.PkAuthProperties;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PkAuthPropertiesTest {

  @Test
  void optionalBlocksFallToDefaultsWhenAbsent() {
    PkAuthProperties props =
        new PkAuthProperties(
            new PkAuthProperties.RelyingParty(
                "example.com", "Example", Set.of("https://example.com")),
            new PkAuthProperties.Jwt("iss", "aud", "secret-that-is-long-enough-32b!!", null, null),
            null,
            null,
            false);
    // ceremony/otp normalise to defaults
    assertThat(props.ceremony().challengeTtl()).isEqualTo(Duration.ofMinutes(5));
    assertThat(props.otp().pepper()).isNull();
    // devMode defaults to false when bound from absent property
    assertThat(props.devMode()).isFalse();
  }

  @Test
  void preservesExplicitValues() {
    Map<String, Duration> perAudience = Map.of("web", Duration.ofMinutes(15));
    PkAuthProperties props =
        new PkAuthProperties(
            new PkAuthProperties.RelyingParty(
                "example.com", "Example", Set.of("https://example.com")),
            new PkAuthProperties.Jwt(
                "iss",
                "aud",
                "secret-that-is-long-enough-32b!!",
                Duration.ofMinutes(30),
                perAudience),
            new PkAuthProperties.Ceremony(Duration.ofMinutes(2)),
            new PkAuthProperties.Otp("dGVzdC1wZXBwZXItYmFzZTY0LWVuY29kZWQ="),
            true);
    assertThat(props.relyingParty().id()).isEqualTo("example.com");
    assertThat(props.jwt().defaultTtl()).isEqualTo(Duration.ofMinutes(30));
    assertThat(props.jwt().ttlsByAudience()).isEqualTo(perAudience);
    assertThat(props.ceremony().challengeTtl()).isEqualTo(Duration.ofMinutes(2));
    assertThat(props.otp().pepper()).isEqualTo("dGVzdC1wZXBwZXItYmFzZTY0LWVuY29kZWQ=");
    assertThat(props.devMode()).isTrue();
  }

  @Test
  void requiredBlocksAreNoLongerDefaulted() {
    // PkAuthProperties no longer auto-populates relyingParty / jwt — adapters fail fast when
    // either block is missing rather than booting against silent localhost / random-key defaults.
    PkAuthProperties props = new PkAuthProperties(null, null, null, null, false);
    assertThat(props.relyingParty()).isNull();
    assertThat(props.jwt()).isNull();
  }
}
