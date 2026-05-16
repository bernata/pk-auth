// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.credential.AuthenticatorData;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ResultTypesTest {

  @Test
  void registrationResultSuccessConstruction() {
    UserHandle uh = UserHandle.random();
    CredentialRecord cred =
        new CredentialRecord(
            CredentialId.of(new byte[] {1, 2, 3}),
            uh,
            new byte[] {4, 5},
            0L,
            "Yubikey",
            null,
            Set.of(Transport.USB),
            true,
            true,
            Instant.now(),
            null);
    AuthenticatorData authData =
        new AuthenticatorData(new byte[] {1}, true, true, false, false, true, false, 0L);

    RegistrationResult result = new RegistrationResult.Success(cred, authData);

    String formatted =
        switch (result) {
          case RegistrationResult.Success s -> "ok:" + s.credential().label();
          case RegistrationResult.InvalidChallenge ic -> "ic:" + ic.detail();
          case RegistrationResult.OriginMismatch om -> "om:" + om.expected();
          case RegistrationResult.AttestationRejected ar -> "ar:" + ar.reason();
          case RegistrationResult.DuplicateCredential dc -> "dup";
          case RegistrationResult.InvalidPayload ip -> "ip:" + ip.detail();
          case RegistrationResult.RateLimited rl -> "rl:" + rl.bucket();
        };
    assertThat(formatted).isEqualTo("ok:Yubikey");
  }

  @Test
  void registrationResultVariantsBuildAndValidate() {
    assertThat(new RegistrationResult.InvalidChallenge("nope").detail()).isEqualTo("nope");
    assertThat(new RegistrationResult.OriginMismatch("a", "b").actual()).isEqualTo("b");
    assertThat(new RegistrationResult.AttestationRejected("fail").reason()).isEqualTo("fail");
    assertThat(new RegistrationResult.InvalidPayload("bad").detail()).isEqualTo("bad");

    CredentialId credId = CredentialId.of(new byte[] {7, 8, 9});
    RegistrationResult.DuplicateCredential dup = new RegistrationResult.DuplicateCredential(credId);
    assertThat(dup.credentialId()).isEqualTo(credId);
    assertThat(dup)
        .isEqualTo(
            new RegistrationResult.DuplicateCredential(CredentialId.of(new byte[] {7, 8, 9})))
        .hasSameHashCodeAs(
            new RegistrationResult.DuplicateCredential(CredentialId.of(new byte[] {7, 8, 9})));

    assertThatThrownBy(() -> new RegistrationResult.InvalidChallenge(null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void assertionResultSuccessConstructionAndAccessors() {
    UserHandle uh = UserHandle.random();
    CredentialId credId = CredentialId.of(new byte[] {10, 11});
    AssertionResult.Success success =
        new AssertionResult.Success(uh, credId, 42L, AssertionResult.CounterStatus.OK);

    assertThat(success.userHandle()).isEqualTo(uh);
    assertThat(success.credentialId()).isEqualTo(credId);
    assertThat(success.signCount()).isEqualTo(42L);
    assertThat(success.counterStatus()).isEqualTo(AssertionResult.CounterStatus.OK);
    assertThat(success)
        .isEqualTo(
            new AssertionResult.Success(
                uh, CredentialId.of(new byte[] {10, 11}), 42L, AssertionResult.CounterStatus.OK))
        .hasSameHashCodeAs(
            new AssertionResult.Success(
                uh, CredentialId.of(new byte[] {10, 11}), 42L, AssertionResult.CounterStatus.OK));
    assertThatThrownBy(
            () ->
                new AssertionResult.Success(
                    uh, CredentialId.of(new byte[] {0}), -1, AssertionResult.CounterStatus.OK))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void assertionResultVariantsExhaustiveSwitch() {
    AssertionResult[] cases = {
      new AssertionResult.UnknownCredential(CredentialId.of(new byte[] {1})),
      new AssertionResult.InvalidChallenge("x"),
      new AssertionResult.OriginMismatch("a", "b"),
      new AssertionResult.CounterRegression(5, 4),
      new AssertionResult.UserVerificationRequired(),
      new AssertionResult.InvalidSignature(),
    };
    for (AssertionResult r : cases) {
      String tag =
          switch (r) {
            case AssertionResult.Success s -> "success";
            case AssertionResult.UnknownCredential uc ->
                "unknown:" + uc.credentialId().value().length;
            case AssertionResult.InvalidChallenge ic -> "ic";
            case AssertionResult.OriginMismatch om -> "om";
            case AssertionResult.CounterRegression cr -> "cr:" + cr.stored() + "/" + cr.received();
            case AssertionResult.UserVerificationRequired uvr -> "uvr";
            case AssertionResult.InvalidSignature is -> "is";
            case AssertionResult.RateLimited rl -> "rl:" + rl.bucket();
          };
      assertThat(tag).isNotBlank();
    }

    AssertionResult.UnknownCredential uc1 =
        new AssertionResult.UnknownCredential(CredentialId.of(new byte[] {1, 2}));
    AssertionResult.UnknownCredential uc2 =
        new AssertionResult.UnknownCredential(CredentialId.of(new byte[] {1, 2}));
    assertThat(uc1).isEqualTo(uc2).hasSameHashCodeAs(uc2);
  }
}
