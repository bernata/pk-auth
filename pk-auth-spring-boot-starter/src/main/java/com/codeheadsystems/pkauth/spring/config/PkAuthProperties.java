// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.config;

import java.time.Duration;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed configuration for the pk-auth Spring Boot starter, bound to {@code pkauth.*} properties.
 *
 * <p>The starter follows Dropwizard's fail-fast policy: relying-party id, name, origins, JWT
 * issuer, audience, and signing secret are all required. Misconfiguration surfaces as a startup
 * failure with a remediation message rather than as silent dev-mode behaviour. Optional blocks
 * ({@code ceremony}, {@code otp}) default to empty/defaulted records.
 *
 * @param relyingParty relying-party identity used in WebAuthn ceremonies (required)
 * @param jwt JWT issuance / validation settings (required)
 * @param ceremony tunables for challenge TTL, user-verification, etc. (optional)
 * @param otp OTP service tunables (optional)
 * @param devMode {@code true} to enable in-memory testkit SPIs and logging email/SMS senders, plus
 *     auto-generation of a per-startup OTP pepper when {@code otp.pepper} is unset. Defaults to
 *     {@code false} — production deployments must supply real SPI beans, real senders, and a
 *     configured pepper. {@code @since 0.9.1}
 */
@ConfigurationProperties("pkauth")
public record PkAuthProperties(
    RelyingParty relyingParty, Jwt jwt, Ceremony ceremony, Otp otp, boolean devMode) {

  /**
   * Normalises the optional blocks ({@code ceremony}, {@code otp}) to their defaults so callers
   * don't have to null-check. Required blocks ({@code relyingParty}, {@code jwt}) are left as the
   * framework bound them — if absent, downstream wiring fails fast with a clear message.
   */
  public PkAuthProperties {
    if (ceremony == null) {
      ceremony = Ceremony.defaults();
    }
    if (otp == null) {
      otp = Otp.defaults();
    }
  }

  /**
   * Relying-party identity. All three fields are required (no defaults) — set {@code
   * pkauth.relying-party.id}, {@code .name}, and at least one {@code .origins[]} value.
   *
   * @param id WebAuthn relying-party id (typically the registrable domain, e.g. {@code
   *     example.com})
   * @param name human-readable label shown by the authenticator
   * @param origins allow-listed origins for ceremony validation; must contain at least one entry
   */
  public record RelyingParty(String id, String name, Set<String> origins) {}

  /**
   * JWT issuance and validation. {@code issuer}, {@code audience}, and {@code secret} are all
   * required — there is no random-key fallback. Only HS256 is configurable from properties;
   * adapters needing ES256 wire a {@code JwtKeyset} bean explicitly.
   *
   * @param issuer the {@code iss} claim (required)
   * @param audience the {@code aud} claim (required)
   * @param secret HS256 shared secret; must be ≥ 32 bytes when UTF-8 encoded (required)
   * @param tokenTtl how long an issued token is valid; null falls back to {@link
   *     com.codeheadsystems.pkauth.jwt.JwtConfig#DEFAULT_TOKEN_TTL}
   */
  public record Jwt(String issuer, String audience, String secret, @Nullable Duration tokenTtl) {}

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
