// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class ChallengeGeneratorTest {

  @Test
  void defaultConstructorProduces32Bytes() {
    byte[] challenge = new ChallengeGenerator().generate();
    assertThat(challenge).hasSize(32);
  }

  @Test
  void usesInjectedSecureRandom() {
    byte[] fill = new byte[] {7, 8, 9};
    SecureRandom random =
        new SecureRandom() {
          @Override
          public void nextBytes(byte[] bytes) {
            for (int i = 0; i < bytes.length; i++) {
              bytes[i] = fill[i % fill.length];
            }
          }
        };
    byte[] challenge = new ChallengeGenerator(random).generate();
    assertThat(challenge[0]).isEqualTo((byte) 7);
    assertThat(challenge[1]).isEqualTo((byte) 8);
    assertThat(challenge[2]).isEqualTo((byte) 9);
    assertThat(challenge[3]).isEqualTo((byte) 7);
  }
}
