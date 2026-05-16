// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.admin.AdminRequests.FinishEmailVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.FinishPhoneVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.RenameCredential;
import com.codeheadsystems.pkauth.admin.AdminRequests.StartEmailVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.StartPhoneVerification;
import org.junit.jupiter.api.Test;

/** Locks the wire-shape accessors so JSON marshallers and adapter code see identical fields. */
class AdminRequestsTest {

  @Test
  void renameCredentialCarriesLabel() {
    assertThat(new RenameCredential("phone").label()).isEqualTo("phone");
    assertThat(new RenameCredential(null).label()).isNull();
  }

  @Test
  void startEmailVerificationCarriesEmail() {
    assertThat(new StartEmailVerification("a@b.test").email()).isEqualTo("a@b.test");
    assertThat(new StartEmailVerification(null).email()).isNull();
  }

  @Test
  void finishEmailVerificationCarriesToken() {
    assertThat(new FinishEmailVerification("tok.en").token()).isEqualTo("tok.en");
    assertThat(new FinishEmailVerification(null).token()).isNull();
  }

  @Test
  void startPhoneVerificationCarriesPhone() {
    assertThat(new StartPhoneVerification("+15551234567").phone()).isEqualTo("+15551234567");
    assertThat(new StartPhoneVerification(null).phone()).isNull();
  }

  @Test
  void finishPhoneVerificationCarriesPhoneAndCode() {
    FinishPhoneVerification body = new FinishPhoneVerification("+15551234567", "000000");
    assertThat(body.phone()).isEqualTo("+15551234567");
    assertThat(body.code()).isEqualTo("000000");
    assertThat(new FinishPhoneVerification(null, null).phone()).isNull();
    assertThat(new FinishPhoneVerification(null, null).code()).isNull();
  }
}
