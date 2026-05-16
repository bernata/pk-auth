// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.config;

import java.time.Duration;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed configuration for the pk-auth Spring Boot starter, bound to {@code pkauth.*} properties.
 *
 * <p>Defaults match the brief's documented values so a host app only has to override the relying
 * party id, origins, and JWT secret.
 *
 * @param relyingParty relying-party identity used in WebAuthn ceremonies
 * @param jwt JWT issuance / validation settings
 * @param ceremony tunables for challenge TTL, user-verification, etc.
 */
@ConfigurationProperties("pkauth")
public record PkAuthProperties(RelyingParty relyingParty, Jwt jwt, Ceremony ceremony, Otp otp) {

  /** Apply defaults for unset blocks so the host app only overrides what it cares about. */
  public PkAuthProperties {
    if (relyingParty == null) {
      relyingParty = RelyingParty.defaults();
    }
    if (jwt == null) {
      jwt = Jwt.defaults();
    }
    if (ceremony == null) {
      ceremony = Ceremony.defaults();
    }
    if (otp == null) {
      otp = Otp.defaults();
    }
  }

  /**
   * Relying-party identity.
   *
   * @param id WebAuthn relying-party id (typically the registrable domain, e.g. {@code
   *     example.com})
   * @param name human-readable label shown by the authenticator
   * @param origins allow-listed origins for ceremony validation
   */
  public record RelyingParty(String id, String name, Set<String> origins) {

    public static RelyingParty defaults() {
      return new RelyingParty(
          "localhost", "pk-auth Spring Boot demo", Set.of("http://localhost:8080"));
    }
  }

  /**
   * JWT issuance and validation. Only HS256 is configurable from properties — adapters needing
   * ES256 wire a {@code JwtKeyset} bean explicitly.
   *
   * @param issuer the {@code iss} claim
   * @param audience the {@code aud} claim
   * @param secret HS256 shared secret (≥ 32 bytes). Required when no explicit JwtKeyset bean
   *     overrides; null falls back to a freshly-minted random secret per-startup (dev only)
   * @param tokenTtl how long an issued token is valid
   */
  public record Jwt(String issuer, String audience, @Nullable String secret, Duration tokenTtl) {

    public static Jwt defaults() {
      return new Jwt("pk-auth", "pk-auth-clients", null, Duration.ofHours(1));
    }
  }

  /**
   * Ceremony tunables forwarded to {@code CeremonyConfig}.
   *
   * @param challengeTtl how long an issued challenge remains valid
   */
  public record Ceremony(Duration challengeTtl) {

    public static Ceremony defaults() {
      return new Ceremony(Duration.ofMinutes(5));
    }
  }

  /**
   * OTP service tunables.
   *
   * @param pepper Base64-encoded server-side HMAC pepper for OTP code hashing. Decoded bytes must
   *     be at least 16 bytes (32+ recommended). Required in production. When unset, the starter
   *     will only auto-generate a per-startup random pepper if {@code pkauth.dev-mode=true}. A
   *     per-startup pepper invalidates outstanding OTPs across restarts and across cluster
   *     instances, which is unsafe in production.
   */
  public record Otp(@Nullable String pepper) {

    public static Otp defaults() {
      return new Otp(null);
    }
  }
}
