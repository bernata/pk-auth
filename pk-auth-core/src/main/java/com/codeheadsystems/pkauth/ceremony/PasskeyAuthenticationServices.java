// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.ceremony;

import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.internal.ChallengeGenerator;
import com.codeheadsystems.pkauth.internal.DefaultPasskeyAuthenticationService;
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
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Public entry point for constructing a {@link PasskeyAuthenticationService}. Hides the internal
 * implementation class while still letting callers wire each SPI explicitly.
 */
public final class PasskeyAuthenticationServices {

  private PasskeyAuthenticationServices() {}

  /** Builder so adapter modules can wire only the SPIs they actually customize. */
  public static Builder builder() {
    return new Builder();
  }

  /** Builder for {@link PasskeyAuthenticationService}. All fields except metrics are required. */
  public static final class Builder {
    private @Nullable WebAuthnManager webAuthnManager;
    private @Nullable ObjectConverter objectConverter;
    private @Nullable CredentialRepository credentialRepository;
    private @Nullable UserLookup userLookup;
    private @Nullable ChallengeStore challengeStore;
    private ClockProvider clockProvider = ClockProvider.system();
    private @Nullable OriginValidator originValidator;
    private AttestationTrustPolicy attestationTrustPolicy = AttestationTrustPolicy.none();
    private @Nullable RelyingPartyConfig rpConfig;
    private CeremonyConfig ceremonyConfig = CeremonyConfig.defaults();
    private SecureRandom secureRandom = new SecureRandom();
    private Metrics metrics = Metrics.noop();

    private Builder() {}

    public Builder webAuthnManager(WebAuthnManager v) {
      this.webAuthnManager = v;
      return this;
    }

    public Builder objectConverter(ObjectConverter v) {
      this.objectConverter = v;
      return this;
    }

    public Builder credentialRepository(CredentialRepository v) {
      this.credentialRepository = v;
      return this;
    }

    public Builder userLookup(UserLookup v) {
      this.userLookup = v;
      return this;
    }

    public Builder challengeStore(ChallengeStore v) {
      this.challengeStore = v;
      return this;
    }

    public Builder clockProvider(ClockProvider v) {
      this.clockProvider = v;
      return this;
    }

    public Builder originValidator(OriginValidator v) {
      this.originValidator = v;
      return this;
    }

    public Builder attestationTrustPolicy(AttestationTrustPolicy v) {
      this.attestationTrustPolicy = v;
      return this;
    }

    public Builder relyingPartyConfig(RelyingPartyConfig v) {
      this.rpConfig = v;
      return this;
    }

    public Builder ceremonyConfig(CeremonyConfig v) {
      this.ceremonyConfig = v;
      return this;
    }

    /** Override the {@link SecureRandom} used for challenge generation (test seam). */
    public Builder secureRandom(SecureRandom v) {
      this.secureRandom = v;
      return this;
    }

    public Builder metrics(Metrics v) {
      this.metrics = v;
      return this;
    }

    public PasskeyAuthenticationService build() {
      ObjectConverter oc = objectConverter == null ? new ObjectConverter() : objectConverter;
      WebAuthnManager mgr =
          webAuthnManager == null
              ? WebAuthnManager.createNonStrictWebAuthnManager(oc)
              : webAuthnManager;
      RelyingPartyConfig rp = Objects.requireNonNull(rpConfig, "relyingPartyConfig must be set");
      OriginValidator origins =
          originValidator == null ? OriginValidator.strict(rp) : originValidator;
      return new DefaultPasskeyAuthenticationService(
          mgr,
          oc,
          Objects.requireNonNull(credentialRepository, "credentialRepository must be set"),
          Objects.requireNonNull(userLookup, "userLookup must be set"),
          Objects.requireNonNull(challengeStore, "challengeStore must be set"),
          clockProvider,
          origins,
          attestationTrustPolicy,
          rp,
          ceremonyConfig,
          new ChallengeGenerator(secureRandom),
          metrics);
    }
  }
}
