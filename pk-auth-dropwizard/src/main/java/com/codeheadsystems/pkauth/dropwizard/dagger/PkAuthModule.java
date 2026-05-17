// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.dagger;

import com.codeheadsystems.pkauth.ceremony.InMemoryCeremonyRateLimiter;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.composition.PkAuthComposition;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.dropwizard.auth.PkAuthDropwizardAuthenticator;
import com.codeheadsystems.pkauth.dropwizard.config.PkAuthConfig;
import com.codeheadsystems.pkauth.dropwizard.resource.PkAuthCeremonyResource;
import com.codeheadsystems.pkauth.jwt.AccessTokenStore;
import com.codeheadsystems.pkauth.jwt.AccessTokenStoreDeletionListener;
import com.codeheadsystems.pkauth.jwt.CeremonyOrchestrator;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.jwt.JwtKeyset;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.jwt.TokenTtlPolicy;
import com.codeheadsystems.pkauth.lifecycle.CredentialRepositoryDeletionListener;
import com.codeheadsystems.pkauth.lifecycle.UserDeletionListener;
import com.codeheadsystems.pkauth.lifecycle.UserDeletionService;
import com.codeheadsystems.pkauth.spi.CeremonyRateLimiter;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import dagger.Module;
import dagger.Provides;
import dagger.multibindings.IntoSet;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.util.Map;
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
    return PkAuthComposition.passkeyAuthenticationService(
        credentials, userLookup, challengeStore, clock, rp, cc, rateLimiter);
  }

  @Provides
  @Singleton
  JwtConfig provideJwtConfig(PkAuthConfig cfg) {
    PkAuthConfig.Jwt jwt = cfg.jwt();
    Duration defaultTtl = jwt.defaultTtl() == null ? JwtConfig.DEFAULT_TOKEN_TTL : jwt.defaultTtl();
    Map<String, Duration> overrides = jwt.ttlsByAudience();
    TokenTtlPolicy ttlPolicy =
        overrides == null || overrides.isEmpty()
            ? TokenTtlPolicy.single(defaultTtl)
            : TokenTtlPolicy.fixed(defaultTtl, overrides);
    return new JwtConfig(
        jwt.issuer(),
        jwt.audience(),
        ttlPolicy,
        JwtConfig.DEFAULT_NBF_SKEW,
        JwtConfig.DEFAULT_CLOCK_SKEW);
  }

  @Provides
  @Singleton
  JwtKeyset provideJwtKeyset(PkAuthConfig cfg) {
    return JwtKeyset.hs256(cfg.jwt().secret());
  }

  @Provides
  @Singleton
  AccessTokenStore provideAccessTokenStore() {
    return persistence.accessTokenStore();
  }

  @Provides
  @Singleton
  PkAuthJwtIssuer provideJwtIssuer(
      JwtConfig cfg, JwtKeyset ks, ClockProvider clock, AccessTokenStore accessTokenStore) {
    return new PkAuthJwtIssuer(cfg, ks, clock, accessTokenStore);
  }

  @Provides
  @Singleton
  PkAuthJwtValidator provideJwtValidator(
      JwtConfig cfg, JwtKeyset ks, ClockProvider clock, AccessTokenStore accessTokenStore) {
    return new PkAuthJwtValidator(
        cfg, ks, clock, com.codeheadsystems.pkauth.jwt.RevocationCheck.allow(), accessTokenStore);
  }

  @Provides
  @Singleton
  @IntoSet
  UserDeletionListener provideCredentialDeletionListener(CredentialRepository repo) {
    return new CredentialRepositoryDeletionListener(repo);
  }

  @Provides
  @Singleton
  @IntoSet
  UserDeletionListener provideAccessTokenStoreDeletionListener(AccessTokenStore store) {
    return new AccessTokenStoreDeletionListener(store);
  }

  @Provides
  @Singleton
  UserDeletionService provideUserDeletionService(Set<UserDeletionListener> listeners) {
    return new UserDeletionService(listeners);
  }

  @Provides
  @Singleton
  PkAuthDropwizardAuthenticator providePasskeyAuthenticator(PkAuthJwtValidator validator) {
    return new PkAuthDropwizardAuthenticator(validator);
  }

  @Provides
  @Singleton
  CeremonyOrchestrator provideCeremonyOrchestrator(
      PasskeyAuthenticationService service,
      PkAuthJwtIssuer issuer,
      CredentialRepository credentialRepository) {
    return PkAuthComposition.ceremonyOrchestrator(service, issuer, credentialRepository);
  }

  @Provides
  @Singleton
  PkAuthCeremonyResource provideCeremonyResource(CeremonyOrchestrator orchestrator) {
    return new PkAuthCeremonyResource(orchestrator);
  }
}
