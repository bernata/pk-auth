// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.dagger;

import com.codeheadsystems.pkauth.ceremony.InMemoryCeremonyRateLimiter;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationServices;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.dropwizard.auth.PkAuthDropwizardAuthenticator;
import com.codeheadsystems.pkauth.dropwizard.config.PkAuthConfig;
import com.codeheadsystems.pkauth.dropwizard.resource.PkAuthCeremonyResource;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.jwt.JwtKeyset;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.spi.CeremonyRateLimiter;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import dagger.Module;
import dagger.Provides;
import jakarta.inject.Singleton;
import java.util.Set;

/**
 * The bundle's Dagger module. Provides the framework-neutral pk-auth services, the JWT
 * issuer/validator, and the {@link PkAuthDropwizardAuthenticator} so Jersey resources can be
 * constructed via the generated component.
 *
 * <p>Persistence SPIs are passed in via {@link PersistenceBindings}, kept out of this module so the
 * same generated component works against any backend (in-memory, JDBI, DynamoDB).
 */
@Module
public final class PkAuthModule {

  private final PkAuthConfig config;
  private final PersistenceBindings persistence;
  private final ClockProvider clockProvider;

  /** Constructs the module from runtime values. */
  public PkAuthModule(PkAuthConfig config, PersistenceBindings persistence) {
    this(config, persistence, ClockProvider.system());
  }

  /** Test seam allowing a fixed clock. */
  public PkAuthModule(
      PkAuthConfig config, PersistenceBindings persistence, ClockProvider clockProvider) {
    this.config = config;
    this.persistence = persistence;
    this.clockProvider = clockProvider;
  }

  @Provides
  @Singleton
  PkAuthConfig provideConfig() {
    return config;
  }

  @Provides
  @Singleton
  ClockProvider provideClockProvider() {
    return clockProvider;
  }

  @Provides
  @Singleton
  CredentialRepository provideCredentialRepository() {
    return persistence.credentialRepository();
  }

  @Provides
  @Singleton
  UserLookup provideUserLookup() {
    return persistence.userLookup();
  }

  @Provides
  @Singleton
  ChallengeStore provideChallengeStore() {
    return persistence.challengeStore();
  }

  @Provides
  @Singleton
  RelyingPartyConfig provideRelyingPartyConfig(PkAuthConfig cfg) {
    PkAuthConfig.RelyingParty rp = cfg.relyingParty();
    return new RelyingPartyConfig(rp.id(), rp.name(), Set.copyOf(rp.origins()));
  }

  @Provides
  @Singleton
  CeremonyConfig provideCeremonyConfig(PkAuthConfig cfg) {
    CeremonyConfig defaults = CeremonyConfig.defaults();
    if (cfg.ceremony().challengeTtl() == null) {
      return defaults;
    }
    return new CeremonyConfig(
        cfg.ceremony().challengeTtl(),
        defaults.userVerification(),
        defaults.residentKey(),
        defaults.attestationConveyance(),
        defaults.counterRegression());
  }

  /**
   * Default in-memory {@link CeremonyRateLimiter}. Hosts MUST override this binding with a shared
   * (Redis / DB-backed) implementation in multi-replica deployments — see {@link
   * InMemoryCeremonyRateLimiter} javadoc.
   *
   * @since 0.9.1
   */
  @Provides
  @Singleton
  CeremonyRateLimiter provideCeremonyRateLimiter() {
    return new InMemoryCeremonyRateLimiter();
  }

  @Provides
  @Singleton
  PasskeyAuthenticationService providePasskeyAuthenticationService(
      RelyingPartyConfig rp,
      CeremonyConfig cc,
      CredentialRepository credentials,
      UserLookup userLookup,
      ChallengeStore challengeStore,
      ClockProvider clock,
      CeremonyRateLimiter rateLimiter) {
    return PasskeyAuthenticationServices.builder()
        .relyingPartyConfig(rp)
        .ceremonyConfig(cc)
        .credentialRepository(credentials)
        .userLookup(userLookup)
        .challengeStore(challengeStore)
        .clockProvider(clock)
        .ceremonyRateLimiter(rateLimiter)
        .build();
  }

  @Provides
  @Singleton
  JwtConfig provideJwtConfig(PkAuthConfig cfg) {
    PkAuthConfig.Jwt jwt = cfg.jwt();
    JwtConfig defaults = JwtConfig.defaults(jwt.issuer(), jwt.audience());
    if (jwt.tokenTtl() == null) {
      return defaults;
    }
    return new JwtConfig(
        jwt.issuer(),
        jwt.audience(),
        jwt.tokenTtl(),
        defaults.notBeforeSkew(),
        defaults.clockSkew());
  }

  @Provides
  @Singleton
  JwtKeyset provideJwtKeyset(PkAuthConfig cfg) {
    return JwtKeyset.hs256(cfg.jwt().secret());
  }

  @Provides
  @Singleton
  PkAuthJwtIssuer provideJwtIssuer(JwtConfig cfg, JwtKeyset ks, ClockProvider clock) {
    return new PkAuthJwtIssuer(cfg, ks, clock);
  }

  @Provides
  @Singleton
  PkAuthJwtValidator provideJwtValidator(JwtConfig cfg, JwtKeyset ks, ClockProvider clock) {
    return new PkAuthJwtValidator(cfg, ks, clock);
  }

  @Provides
  @Singleton
  PkAuthDropwizardAuthenticator providePasskeyAuthenticator(PkAuthJwtValidator validator) {
    return new PkAuthDropwizardAuthenticator(validator);
  }

  @Provides
  @Singleton
  com.codeheadsystems.pkauth.jwt.CeremonyOrchestrator provideCeremonyOrchestrator(
      PasskeyAuthenticationService service,
      PkAuthJwtIssuer issuer,
      CredentialRepository credentialRepository) {
    return new com.codeheadsystems.pkauth.jwt.CeremonyOrchestrator(
        service, issuer, credentialRepository);
  }

  @Provides
  @Singleton
  PkAuthCeremonyResource provideCeremonyResource(
      com.codeheadsystems.pkauth.jwt.CeremonyOrchestrator orchestrator) {
    return new PkAuthCeremonyResource(orchestrator);
  }
}
