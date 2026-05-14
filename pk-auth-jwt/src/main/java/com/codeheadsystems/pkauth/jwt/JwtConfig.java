// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import java.time.Duration;
import java.util.Objects;

/**
 * Configuration for pk-auth's JWT issuance and validation.
 *
 * @param issuer the {@code iss} claim value
 * @param audience the {@code aud} claim value
 * @param tokenTtl how long an issued token is valid
 * @param notBeforeSkew the {@code nbf} claim is set to {@code iat - notBeforeSkew} (small negative
 *     skew helps clients with slightly fast clocks accept tokens immediately)
 * @param clockSkew leniency window applied to {@code exp} and {@code nbf} during validation
 */
public record JwtConfig(
    String issuer, String audience, Duration tokenTtl, Duration notBeforeSkew, Duration clockSkew) {

  /** Default token TTL: 1 hour. */
  public static final Duration DEFAULT_TOKEN_TTL = Duration.ofHours(1);

  /** Default not-before skew applied at issuance: 30 seconds back. */
  public static final Duration DEFAULT_NBF_SKEW = Duration.ofSeconds(30);

  /** Default validation tolerance for clock skew: 30 seconds. */
  public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(30);

  public JwtConfig {
    Objects.requireNonNull(issuer, "issuer");
    if (issuer.isBlank()) {
      throw new IllegalArgumentException("issuer must be non-blank");
    }
    Objects.requireNonNull(audience, "audience");
    if (audience.isBlank()) {
      throw new IllegalArgumentException("audience must be non-blank");
    }
    Objects.requireNonNull(tokenTtl, "tokenTtl");
    if (tokenTtl.isZero() || tokenTtl.isNegative()) {
      throw new IllegalArgumentException("tokenTtl must be positive");
    }
    Objects.requireNonNull(notBeforeSkew, "notBeforeSkew");
    if (notBeforeSkew.isNegative()) {
      throw new IllegalArgumentException("notBeforeSkew must be non-negative");
    }
    Objects.requireNonNull(clockSkew, "clockSkew");
    if (clockSkew.isNegative()) {
      throw new IllegalArgumentException("clockSkew must be non-negative");
    }
  }

  /** Convenience constructor with the documented defaults. */
  public static JwtConfig defaults(String issuer, String audience) {
    return new JwtConfig(issuer, audience, DEFAULT_TOKEN_TTL, DEFAULT_NBF_SKEW, DEFAULT_CLOCK_SKEW);
  }
}
