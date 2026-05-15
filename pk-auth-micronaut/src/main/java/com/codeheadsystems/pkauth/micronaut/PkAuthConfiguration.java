// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import io.micronaut.context.annotation.ConfigurationProperties;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * Micronaut configuration bound under the {@code pkauth} prefix. Mirrors the Spring and Dropwizard
 * adapters' shape so the host's {@code application.yml} reads the same.
 */
@ConfigurationProperties("pkauth")
public final class PkAuthConfiguration {

  private RelyingParty relyingParty = new RelyingParty();
  private Jwt jwt = new Jwt();

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
}
