// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.config;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Aggregated configuration for the Dropwizard adapter. Host applications carry this record on their
 * own {@code Configuration} class (see {@link
 * com.codeheadsystems.pkauth.dropwizard.HasPkAuthConfig}) and the bundle pulls it out at {@code
 * run()} time.
 *
 * <p>Defaults are intentionally not provided here — every field is required so misconfiguration
 * fails at start-up rather than silently using a dev-only value in production.
 *
 * @param relyingParty RP identity (id, name, origins) used for WebAuthn ceremonies.
 * @param jwt JWT issuer, audience, and signing-key material.
 * @param ceremony Ceremony policy knobs (challenge TTL, etc.).
 */
public record PkAuthConfig(RelyingParty relyingParty, Jwt jwt, Ceremony ceremony) {

  public PkAuthConfig {
    Objects.requireNonNull(relyingParty, "relyingParty");
    Objects.requireNonNull(jwt, "jwt");
    Objects.requireNonNull(ceremony, "ceremony");
  }

  /**
   * Relying-party block. Mirrors {@link com.codeheadsystems.pkauth.config.RelyingPartyConfig} but
   * lives in the adapter package so YAML can bind to it without dragging Jackson onto core.
   *
   * @param id WebAuthn RP id (e.g. {@code "example.com"}).
   * @param name Human-readable RP name shown to the user during ceremonies.
   * @param origins Allowed client-reported origins.
   */
  public record RelyingParty(String id, String name, Set<String> origins) {
    public RelyingParty {
      Objects.requireNonNull(id, "id");
      Objects.requireNonNull(name, "name");
      Objects.requireNonNull(origins, "origins");
      if (origins.isEmpty()) {
        throw new IllegalArgumentException("at least one origin required");
      }
      origins = Set.copyOf(new LinkedHashSet<>(origins));
    }
  }

  /**
   * JWT block. Both {@code secret} (HS256) and {@code audience} are required so the bundle can mint
   * tokens at the end of a successful authentication ceremony.
   *
   * @param issuer iss claim value.
   * @param audience aud claim value.
   * @param secret Raw HMAC secret bytes; must be at least 32 bytes for HS256.
   * @param tokenTtl How long an issued JWT remains valid; null defers to the {@link
   *     com.codeheadsystems.pkauth.jwt.JwtConfig} default of one hour.
   */
  public record Jwt(String issuer, String audience, byte[] secret, @Nullable Duration tokenTtl) {
    public Jwt {
      Objects.requireNonNull(issuer, "issuer");
      Objects.requireNonNull(audience, "audience");
      Objects.requireNonNull(secret, "secret");
      if (secret.length < 32) {
        throw new IllegalArgumentException(
            "HS256 secret must be >= 32 bytes (got " + secret.length + ")");
      }
      // Defensive copy to keep callers from mutating the byte[] under us.
      secret = secret.clone();
    }

    /** Returns a fresh defensive copy of the underlying secret. */
    @Override
    public byte[] secret() {
      return secret.clone();
    }
  }

  /**
   * Ceremony policy knobs. Optional; nulls fall back to {@link
   * com.codeheadsystems.pkauth.config.CeremonyConfig#defaults()}.
   *
   * @param challengeTtl Override for challenge TTL; null = use the brief's 5-minute default.
   */
  public record Ceremony(@Nullable Duration challengeTtl) {
    public Ceremony() {
      this(null);
    }
  }
}
