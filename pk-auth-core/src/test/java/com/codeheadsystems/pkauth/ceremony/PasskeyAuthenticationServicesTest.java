// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.ceremony;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.metrics.Metrics;
import com.codeheadsystems.pkauth.spi.AttestationTrustPolicy;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OriginValidator;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import java.security.SecureRandom;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PasskeyAuthenticationServicesTest {

  @Test
  void builderWiresDefaultsWhenOnlyRequiredFieldsSet() {
    RelyingPartyConfig rp =
        new RelyingPartyConfig("example.com", "Example", Set.of("https://example.com"));

    PasskeyAuthenticationService svc =
        PasskeyAuthenticationServices.builder()
            .credentialRepository(mock(CredentialRepository.class))
            .userLookup(mock(UserLookup.class))
            .challengeStore(mock(ChallengeStore.class))
            .relyingPartyConfig(rp)
            .build();

    assertThat(svc).isNotNull();
  }

  @Test
  void builderAcceptsAllOverrides() {
    RelyingPartyConfig rp =
        new RelyingPartyConfig("example.com", "Example", Set.of("https://example.com"));
    ObjectConverter oc = new ObjectConverter();

    PasskeyAuthenticationService svc =
        PasskeyAuthenticationServices.builder()
            .webAuthnManager(WebAuthnManager.createNonStrictWebAuthnManager(oc))
            .objectConverter(oc)
            .credentialRepository(mock(CredentialRepository.class))
            .userLookup(mock(UserLookup.class))
            .challengeStore(mock(ChallengeStore.class))
            .clockProvider(ClockProvider.system())
            .originValidator(OriginValidator.strict(rp))
            .attestationTrustPolicy(AttestationTrustPolicy.none())
            .relyingPartyConfig(rp)
            .ceremonyConfig(
                new CeremonyConfig(
                    java.time.Duration.ofMinutes(2),
                    UserVerificationRequirement.REQUIRED,
                    com.codeheadsystems.pkauth.api.ResidentKeyRequirement.REQUIRED,
                    com.codeheadsystems.pkauth.api.AttestationConveyance.NONE,
                    com.codeheadsystems.pkauth.config.CounterRegressionPolicy.WARN))
            .secureRandom(new SecureRandom())
            .metrics(Metrics.noop())
            .build();

    assertThat(svc).isNotNull();
  }

  @Test
  void builderRejectsMissingRpConfig() {
    assertThatThrownBy(
            () ->
                PasskeyAuthenticationServices.builder()
                    .credentialRepository(mock(CredentialRepository.class))
                    .userLookup(mock(UserLookup.class))
                    .challengeStore(mock(ChallengeStore.class))
                    .build())
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("relyingPartyConfig");
  }

  @Test
  void builderRejectsMissingCredentialRepository() {
    RelyingPartyConfig rp =
        new RelyingPartyConfig("example.com", "Example", Set.of("https://example.com"));
    assertThatThrownBy(
            () ->
                PasskeyAuthenticationServices.builder()
                    .relyingPartyConfig(rp)
                    .userLookup(mock(UserLookup.class))
                    .challengeStore(mock(ChallengeStore.class))
                    .build())
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("credentialRepository");
  }
}
