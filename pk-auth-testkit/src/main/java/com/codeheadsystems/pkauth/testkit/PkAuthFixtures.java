// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.CounterRegressionPolicy;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import java.time.Duration;
import java.util.Set;

/** Canned configs and helpers shared across tests in this module and downstream consumers. */
public final class PkAuthFixtures {

  /** Default RP for testkit fixtures: {@code example.com} / {@code https://example.com}. */
  public static final String DEFAULT_RP_ID = "example.com";

  /** Default origin matching {@link #DEFAULT_RP_ID}. */
  public static final String DEFAULT_ORIGIN = "https://example.com";

  private PkAuthFixtures() {}

  /** A reasonable {@link RelyingPartyConfig} for testkit-based ceremonies. */
  public static RelyingPartyConfig defaultRelyingParty() {
    return new RelyingPartyConfig(DEFAULT_RP_ID, "pk-auth testkit", Set.of(DEFAULT_ORIGIN));
  }

  /**
   * A {@link CeremonyConfig} with the brief's defaults. Tests can pass a different {@link
   * CounterRegressionPolicy} via {@link #ceremonyConfig(CounterRegressionPolicy)}.
   */
  public static CeremonyConfig defaultCeremonyConfig() {
    return ceremonyConfig(CounterRegressionPolicy.REJECT);
  }

  /** Same as {@link #defaultCeremonyConfig()} but with the supplied regression policy. */
  public static CeremonyConfig ceremonyConfig(CounterRegressionPolicy policy) {
    return new CeremonyConfig(
        Duration.ofMinutes(5),
        UserVerificationRequirement.PREFERRED,
        ResidentKeyRequirement.PREFERRED,
        AttestationConveyance.NONE,
        policy);
  }
}
