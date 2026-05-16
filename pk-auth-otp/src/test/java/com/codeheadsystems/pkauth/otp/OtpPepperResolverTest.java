// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.otp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;
import org.junit.jupiter.api.Test;

class OtpPepperResolverTest {

  @Test
  void decodesConfiguredBase64Pepper() {
    byte[] secret = new byte[32];
    java.util.Arrays.fill(secret, (byte) 0x42);
    String encoded = Base64.getEncoder().encodeToString(secret);
    byte[] resolved = OtpPepperResolver.resolve(() -> encoded, () -> false);
    assertThat(resolved).isEqualTo(secret);
  }

  @Test
  void trimsWhitespaceAroundConfiguredPepper() {
    byte[] secret = new byte[16];
    java.util.Arrays.fill(secret, (byte) 0x55);
    String encoded = "  " + Base64.getEncoder().encodeToString(secret) + "  ";
    byte[] resolved = OtpPepperResolver.resolve(() -> encoded, () -> false);
    assertThat(resolved).isEqualTo(secret);
  }

  @Test
  void rejectsInvalidBase64() {
    assertThatThrownBy(() -> OtpPepperResolver.resolve(() -> "not!base64!!", () -> false))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("must be a valid Base64");
  }

  @Test
  void rejectsTooShortPepper() {
    byte[] secret = new byte[8];
    String encoded = Base64.getEncoder().encodeToString(secret);
    assertThatThrownBy(() -> OtpPepperResolver.resolve(() -> encoded, () -> false))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("at least 16 bytes");
  }

  @Test
  void failsFastWhenUnsetAndDevModeFalse() {
    assertThatThrownBy(() -> OtpPepperResolver.resolve(() -> null, () -> false))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("pkauth.otp.pepper is not configured");
  }

  @Test
  void failsFastWhenBlankAndDevModeFalse() {
    assertThatThrownBy(() -> OtpPepperResolver.resolve(() -> "   ", () -> false))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("pkauth.otp.pepper is not configured");
  }

  @Test
  void generatesRandomPepperWhenUnsetAndDevModeTrue() {
    byte[] resolved = OtpPepperResolver.resolve(() -> null, () -> true);
    assertThat(resolved).hasSize(32);
  }
}
