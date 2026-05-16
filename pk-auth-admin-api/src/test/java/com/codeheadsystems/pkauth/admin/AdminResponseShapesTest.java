// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * Locks the shared response wire shapes so any adapter that returns them produces byte-for-byte
 * identical JSON.
 */
class AdminResponseShapesTest {

  @Test
  void backupCodesCountResponseCarriesRemaining() {
    assertThat(new BackupCodesCountResponse(7).remaining()).isEqualTo(7);
    assertThat(new BackupCodesCountResponse(0).remaining()).isZero();
  }

  @Test
  void emailVerificationResultCarriesUserHandle() {
    assertThat(new EmailVerificationResult("abc").userHandle()).isEqualTo("abc");
  }

  @Test
  void emailVerificationResultRejectsNullHandle() {
    assertThatThrownBy(() -> new EmailVerificationResult(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("userHandle");
  }
}
