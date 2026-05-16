// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.autoconfigure;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.ceremony.InMemoryCeremonyRateLimiter;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationServices;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.CounterRegressionPolicy;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.jwt.JwtKeyset;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.magiclink.EmailSender;
import com.codeheadsystems.pkauth.magiclink.LoggingEmailSender;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService;
import com.codeheadsystems.pkauth.otp.LoggingSmsSender;
import com.codeheadsystems.pkauth.otp.OtpService;
import com.codeheadsystems.pkauth.otp.SmsSender;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.CeremonyRateLimiter;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.spring.config.PkAuthProperties;
import com.codeheadsystems.pkauth.testkit.InMemoryBackupCodeRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryChallengeStore;
import com.codeheadsystems.pkauth.testkit.InMemoryCredentialRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryOtpRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryUserLookup;
import java.security.SecureRandom;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Top-level autoconfiguration for the pk-auth Spring Boot starter. Wires:
 *
 * <ul>
 *   <li>Core service ({@code PasskeyAuthenticationService}) via the {@link
 *       PasskeyAuthenticationServices} factory.
 *   <li>SPI implementations — {@code CredentialRepository} / {@code UserLookup} / {@code
 *       ChallengeStore} / {@code BackupCodeRepository} / {@code OtpRepository}. Each is provided
 *       only when no host-app bean of the same type exists ({@link ConditionalOnMissingBean}) AND
 *       the host has explicitly opted in to the in-memory testkit defaults by setting {@code
 *       pkauth.dev-mode=true}. Without that flag, a host that fails to declare its own SPI beans
 *       will fail to start — preventing accidental production deploys backed by single-JVM,
 *       non-persistent storage. Host apps that want JDBI or DynamoDB declare those beans themselves
 *       (typically in their own {@code @Configuration}).
 *   <li>JWT issuer + validator backed by {@link JwtKeyset#hs256(byte[])} when {@link
 *       PkAuthProperties.Jwt#secret()} is set, otherwise a freshly-minted random secret per startup
 *       (dev-only — host apps that care about token portability set the secret explicitly).
 *   <li>Default sender beans ({@link LoggingEmailSender}, {@link LoggingSmsSender}) so the alt-flow
 *       services compose. Per brief §12 #7, "Don't write production-quality email/SMS senders" —
 *       the logging shims are deliberate.
 * </ul>
 *
 * <p>Web-tier wiring (the ceremony controller, JWT filter, admin controller) lives in {@link
 * PkAuthWebAutoConfiguration} so this class can stay focused on the framework-neutral surface.
 *
 * <p>The brief (§4.2) calls for an explicit guard against Spring Security's own webauthn module.
 * That guard lives in {@link PkAuthWebAutoConfiguration} where it has access to the security filter
 * chain.
 */
@AutoConfiguration
@EnableConfigurationProperties(PkAuthProperties.class)
public class PkAuthAutoConfiguration {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthAutoConfiguration.class);

  // -- Core wiring -----------------------------------------------------------------------------

  @Bean
  @ConditionalOnMissingBean
  public ClockProvider pkAuthClockProvider() {
    return ClockProvider.system();
  }

  @Bean
  @ConditionalOnMissingBean
  public RelyingPartyConfig pkAuthRelyingPartyConfig(PkAuthProperties props) {
    PkAuthProperties.RelyingParty rp = props.relyingParty();
    return new RelyingPartyConfig(rp.id(), rp.name(), rp.origins());
  }

  @Bean
  @ConditionalOnMissingBean
  public CeremonyConfig pkAuthCeremonyConfig(PkAuthProperties props) {
    return new CeremonyConfig(
        props.ceremony().challengeTtl(),
        UserVerificationRequirement.PREFERRED,
        ResidentKeyRequirement.PREFERRED,
        AttestationConveyance.NONE,
        CounterRegressionPolicy.REJECT);
  }

  /**
   * Logged once on bean creation when the dev-mode testkit defaults activate, so an operator who
   * trips this in production sees it loudly in startup logs.
   */
  private static final String DEV_MODE_WARNING =
      "pkauth.dev-mode=true: using in-memory testkit SPI for {} — DO NOT use in production. "
          + "State is per-JVM and lost on restart.";

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public CredentialRepository pkAuthCredentialRepository() {
    LOG.error(DEV_MODE_WARNING, "credentials");
    return new InMemoryCredentialRepository();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public UserLookup pkAuthUserLookup() {
    LOG.error(DEV_MODE_WARNING, "users");
    return new InMemoryUserLookup();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public ChallengeStore pkAuthChallengeStore() {
    LOG.error(DEV_MODE_WARNING, "challenges");
    return new InMemoryChallengeStore();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public BackupCodeRepository pkAuthBackupCodeRepository() {
    LOG.error(DEV_MODE_WARNING, "backup-codes");
    return new InMemoryBackupCodeRepository();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public OtpRepository pkAuthOtpRepository() {
    LOG.error(DEV_MODE_WARNING, "otp");
    return new InMemoryOtpRepository();
  }

  /**
   * Default in-memory ceremony rate limiter. Hosts MUST replace this with a shared (Redis /
   * DB-backed) {@link CeremonyRateLimiter} bean in multi-replica deployments — see {@link
   * InMemoryCeremonyRateLimiter}'s class javadoc.
   *
   * @since 0.9.1
   */
  @Bean
  @ConditionalOnMissingBean
  public CeremonyRateLimiter pkAuthCeremonyRateLimiter() {
    return new InMemoryCeremonyRateLimiter();
  }

  @Bean
  @ConditionalOnMissingBean
  public PasskeyAuthenticationService pkAuthService(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      ChallengeStore challengeStore,
      ClockProvider clockProvider,
      RelyingPartyConfig rp,
      CeremonyConfig ceremonyConfig,
      CeremonyRateLimiter ceremonyRateLimiter) {
    return PasskeyAuthenticationServices.builder()
        .credentialRepository(credentialRepository)
        .userLookup(userLookup)
        .challengeStore(challengeStore)
        .clockProvider(clockProvider)
        .relyingPartyConfig(rp)
        .ceremonyConfig(ceremonyConfig)
        .ceremonyRateLimiter(ceremonyRateLimiter)
        .build();
  }

  // -- JWT -------------------------------------------------------------------------------------

  @Bean
  @ConditionalOnMissingBean
  public JwtConfig pkAuthJwtConfig(PkAuthProperties props) {
    Duration ttl = props.jwt().tokenTtl();
    return new JwtConfig(
        props.jwt().issuer(),
        props.jwt().audience(),
        ttl,
        JwtConfig.DEFAULT_NBF_SKEW,
        JwtConfig.DEFAULT_CLOCK_SKEW);
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtKeyset pkAuthJwtKeyset(PkAuthProperties props) {
    String secret = props.jwt().secret();
    if (secret != null && !secret.isBlank()) {
      byte[] keyBytes = secret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      if (keyBytes.length < 32) {
        throw new IllegalArgumentException(
            "pkauth.jwt.secret must be at least 32 bytes for HS256 (got "
                + keyBytes.length
                + "). Configure a ≥ 32-byte random value or supply a JwtKeyset bean.");
      }
      return JwtKeyset.hs256(keyBytes);
    }
    byte[] random = new byte[32];
    new SecureRandom().nextBytes(random);
    LOG.warn(
        "pkauth.jwt.secret not configured; generating a one-shot random HS256 key. Tokens "
            + "issued on this instance will not validate on other instances or restarts.");
    return JwtKeyset.hs256(random);
  }

  @Bean
  @ConditionalOnMissingBean
  public PkAuthJwtIssuer pkAuthJwtIssuer(
      JwtConfig config, JwtKeyset keyset, ClockProvider clockProvider) {
    return new PkAuthJwtIssuer(config, keyset, clockProvider);
  }

  @Bean
  @ConditionalOnMissingBean
  public PkAuthJwtValidator pkAuthJwtValidator(
      JwtConfig config, JwtKeyset keyset, ClockProvider clockProvider) {
    return new PkAuthJwtValidator(config, keyset, clockProvider);
  }

  // -- Alt-flow services -----------------------------------------------------------------------

  /**
   * Logging email/SMS senders are dev-only: they write the full message body — which contains the
   * magic-link token or OTP code — to the application log. Gating them behind {@code
   * pkauth.dev-mode=true} prevents an accidental production deploy from silently leaking single-use
   * credentials to log aggregation systems. A host without a real {@code EmailSender} / {@code
   * SmsSender} bean and without {@code dev-mode=true} fails to start (no bean for the downstream
   * {@code MagicLinkService} / {@code OtpService} factory parameters), which is the intended
   * fail-fast behaviour.
   */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public EmailSender pkAuthEmailSender() {
    LOG.error(
        "pkauth.dev-mode=true: using LoggingEmailSender — magic-link tokens will be written to"
            + " the application log. DO NOT use in production.");
    return new LoggingEmailSender();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "pkauth", name = "dev-mode", havingValue = "true")
  public SmsSender pkAuthSmsSender() {
    LOG.error(
        "pkauth.dev-mode=true: using LoggingSmsSender — OTP codes will be written to the"
            + " application log. DO NOT use in production.");
    return new LoggingSmsSender();
  }

  @Bean
  @ConditionalOnMissingBean
  public BackupCodeService pkAuthBackupCodeService(
      BackupCodeRepository repo, ClockProvider clockProvider) {
    return new BackupCodeService(repo, clockProvider);
  }

  @Bean
  @ConditionalOnMissingBean
  public MagicLinkService pkAuthMagicLinkService(
      PkAuthJwtIssuer issuer,
      PkAuthJwtValidator validator,
      EmailSender emailSender,
      UserLookup userLookup,
      ClockProvider clockProvider,
      PkAuthProperties props) {
    // baseUrl for the magic link uses the configured RP origin's first entry. Demo apps that
    // serve at a different path override the service bean explicitly.
    String baseUrl = props.relyingParty().origins().iterator().next();
    return new MagicLinkService(issuer, validator, emailSender, userLookup, clockProvider, baseUrl);
  }

  @Bean
  @ConditionalOnMissingBean
  public OtpService pkAuthOtpService(
      OtpRepository repo,
      SmsSender smsSender,
      ClockProvider clockProvider,
      PkAuthProperties props,
      org.springframework.core.env.Environment env) {
    byte[] pepper = resolveOtpPepper(props, env);
    return new OtpService(repo, smsSender, clockProvider, pepper);
  }

  /**
   * Resolves the OTP pepper according to the configured policy:
   *
   * <ul>
   *   <li>{@code pkauth.otp.pepper} set → decode as Base64 and use (≥ 16 bytes required).
   *   <li>Unset AND {@code pkauth.dev-mode=true} → generate a per-startup random pepper and log a
   *       loud warning. A per-startup pepper invalidates OTPs across restarts / instances.
   *   <li>Unset AND {@code pkauth.dev-mode} false/unset → fail fast at startup.
   * </ul>
   */
  private static byte[] resolveOtpPepper(
      PkAuthProperties props, org.springframework.core.env.Environment env) {
    String configured = props.otp().pepper();
    if (configured != null && !configured.isBlank()) {
      byte[] decoded;
      try {
        decoded = java.util.Base64.getDecoder().decode(configured.trim());
      } catch (IllegalArgumentException e) {
        throw new IllegalStateException(
            "pkauth.otp.pepper must be a valid Base64 string (≥ 16 decoded bytes).", e);
      }
      if (decoded.length < 16) {
        throw new IllegalStateException(
            "pkauth.otp.pepper decoded to "
                + decoded.length
                + " bytes; at least 16 bytes required (32+ recommended).");
      }
      return decoded;
    }
    boolean devMode = Boolean.parseBoolean(env.getProperty("pkauth.dev-mode", "false"));
    if (!devMode) {
      throw new IllegalStateException(
          "pkauth.otp.pepper is not configured. Set a Base64-encoded ≥32-byte secret in"
              + " configuration, or enable pkauth.dev-mode=true to auto-generate a per-startup"
              + " random pepper (dev only — invalidates OTPs across restarts / cluster"
              + " instances).");
    }
    byte[] random = new byte[32];
    new SecureRandom().nextBytes(random);
    LOG.warn(
        "pkauth.dev-mode=true and pkauth.otp.pepper not set: generated a one-shot random OTP"
            + " pepper. Outstanding OTPs will not survive a restart and will not validate on"
            + " other instances. DO NOT use this configuration in production.");
    return random;
  }
}
