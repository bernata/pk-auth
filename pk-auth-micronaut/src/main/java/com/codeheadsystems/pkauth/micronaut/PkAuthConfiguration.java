// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import io.micronaut.context.annotation.ConfigurationProperties;
import java.time.Duration;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * Micronaut configuration bound under the {@code pkauth} prefix. Mirrors the Spring and Dropwizard
 * adapters' shape so the host's {@code application.yml} reads the same. Secrets configurable via
 * env-var with the standard Micronaut mapping: {@code pkauth.jwt.secret} ↔ {@code
 * PKAUTH_JWT_SECRET}.
 */
@ConfigurationProperties("pkauth")
public final class PkAuthConfiguration {

  private RelyingParty relyingParty = new RelyingParty();
  private Jwt jwt = new Jwt();
  private Ceremony ceremony = new Ceremony();
  private Otp otp = new Otp();

  public RelyingParty getRelyingParty() {
    return relyingParty;
  }

  public void setRelyingParty(RelyingParty v) {
    this.relyingParty = v;
  }

  public Jwt getJwt() {
    return jwt;
  }

  public void setJwt(Jwt v) {
    this.jwt = v;
  }

  public Ceremony getCeremony() {
    return ceremony;
  }

  public void setCeremony(Ceremony v) {
    this.ceremony = v;
  }

  public Otp getOtp() {
    return otp;
  }

  public void setOtp(Otp v) {
    this.otp = v;
  }

  /**
   * Ceremony tunables forwarded to {@code CeremonyConfig}. Same default and key as the Spring
   * adapter's {@code pkauth.ceremony.challengeTtl}.
   */
  @ConfigurationProperties("ceremony")
  public static final class Ceremony {
    private Duration challengeTtl = Duration.ofMinutes(5);

    public Duration getChallengeTtl() {
      return challengeTtl;
    }

    public void setChallengeTtl(Duration challengeTtl) {
      this.challengeTtl = challengeTtl;
    }
  }

  /** Relying-party identity nested config. */
  @ConfigurationProperties("relying-party")
  public static final class RelyingParty {
    private String id = "example.com";
    private String name = "pk-auth Micronaut demo";
    private List<String> origins = List.of("http://localhost:8080");

    public String getId() {
      return id;
    }

    public void setId(String id) {
      this.id = id;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public List<String> getOrigins() {
      return origins;
    }

    public void setOrigins(List<String> origins) {
      this.origins = origins;
    }
  }

  /** JWT issuance and validation config. */
  @ConfigurationProperties("jwt")
  public static final class Jwt {
    private String issuer = "pk-auth-micronaut";
    private String audience = "pk-auth-micronaut-clients";
    private @Nullable String secret;

    public String getIssuer() {
      return issuer;
    }

    public void setIssuer(String issuer) {
      this.issuer = issuer;
    }

    public String getAudience() {
      return audience;
    }

    public void setAudience(String audience) {
      this.audience = audience;
    }

    public @Nullable String getSecret() {
      return secret;
    }

    public void setSecret(@Nullable String secret) {
      this.secret = secret;
    }
  }

  /**
   * OTP service tunables.
   *
   * <p>{@code pkauth.otp.pepper} is a Base64-encoded server-side HMAC pepper (≥ 16 decoded bytes;
   * 32+ recommended). Required in production. When unset, the factory will only auto-generate a
   * per-startup random pepper if {@code pkauth.dev-mode=true}. A per-startup pepper invalidates
   * outstanding OTPs across restarts and across cluster instances.
   */
  @ConfigurationProperties("otp")
  public static final class Otp {
    private @Nullable String pepper;

    public @Nullable String getPepper() {
      return pepper;
    }

    public void setPepper(@Nullable String pepper) {
      this.pepper = pepper;
    }
  }
}
