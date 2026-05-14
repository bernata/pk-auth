// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.autoconfigure;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
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
 *       only when no host-app bean of the same type exists ({@link ConditionalOnMissingBean}). The
 *       starter ships in-memory defaults from {@code pk-auth-testkit} so a host app boots without
 *       extra wiring — host apps that want JDBI or DynamoDB declare those beans themselves
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

  @Bean
  @ConditionalOnMissingBean
  public CredentialRepository pkAuthCredentialRepository() {
    LOG.info("pkauth.credentials backend=in-memory (testkit default)");
    return new InMemoryCredentialRepository();
  }

  @Bean
  @ConditionalOnMissingBean
  public UserLookup pkAuthUserLookup() {
    LOG.info("pkauth.users backend=in-memory (testkit default)");
    return new InMemoryUserLookup();
  }

  @Bean
  @ConditionalOnMissingBean
  public ChallengeStore pkAuthChallengeStore() {
    LOG.info("pkauth.challenges backend=in-memory (testkit default)");
    return new InMemoryChallengeStore();
  }

  @Bean
  @ConditionalOnMissingBean
  public BackupCodeRepository pkAuthBackupCodeRepository() {
    return new InMemoryBackupCodeRepository();
  }

  @Bean
  @ConditionalOnMissingBean
  public OtpRepository pkAuthOtpRepository() {
    return new InMemoryOtpRepository();
  }

  @Bean
  @ConditionalOnMissingBean
  public PasskeyAuthenticationService pkAuthService(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      ChallengeStore challengeStore,
      ClockProvider clockProvider,
      RelyingPartyConfig rp,
      CeremonyConfig ceremonyConfig) {
    return PasskeyAuthenticationServices.builder()
        .credentialRepository(credentialRepository)
        .userLookup(userLookup)
        .challengeStore(challengeStore)
        .clockProvider(clockProvider)
        .relyingPartyConfig(rp)
        .ceremonyConfig(ceremonyConfig)
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
      // Nimbus requires ≥ 256-bit shared secrets for HS256. We hash short secrets up to length
      // rather than refusing to start — friendlier dev experience and still strictly stronger than
      // letting Nimbus reject at first issue. Operators wanting deterministic key material set a
      // ≥ 32-byte secret directly.
      byte[] keyBytes = expand(secret.getBytes(java.nio.charset.StandardCharsets.UTF_8), 32);
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

  @Bean
  @ConditionalOnMissingBean
  public EmailSender pkAuthEmailSender() {
    return new LoggingEmailSender();
  }

  @Bean
  @ConditionalOnMissingBean
  public SmsSender pkAuthSmsSender() {
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
      OtpRepository repo, SmsSender smsSender, ClockProvider clockProvider) {
    return new OtpService(repo, smsSender, clockProvider);
  }

  private static byte[] expand(byte[] input, int minLength) {
    if (input.length >= minLength) {
      return input;
    }
    byte[] expanded = new byte[minLength];
    for (int i = 0; i < minLength; i++) {
      expanded[i] = input[i % input.length];
    }
    return expanded;
  }
}
