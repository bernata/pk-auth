// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.admin.DefaultAdminService;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationServices;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
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
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wires every pk-auth service Micronaut hosts. Persistence SPIs ({@link CredentialRepository},
 * {@link UserLookup}, {@link ChallengeStore}, {@link BackupCodeRepository}, {@link OtpRepository})
 * must be supplied by the host application or by including {@code pk-auth-persistence-jdbi} /
 * {@code pk-auth-persistence-dynamodb} with their own factories.
 */
@Factory
public class PkAuthFactory {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthFactory.class);

  @Singleton
  RelyingPartyConfig relyingPartyConfig(PkAuthConfiguration config) {
    PkAuthConfiguration.RelyingParty rp = config.getRelyingParty();
    return new RelyingPartyConfig(rp.getId(), rp.getName(), Set.copyOf(rp.getOrigins()));
  }

  @Singleton
  CeremonyConfig ceremonyConfig(PkAuthConfiguration config) {
    CeremonyConfig defaults = CeremonyConfig.defaults();
    return new CeremonyConfig(
        config.getCeremony().getChallengeTtl(),
        defaults.userVerification(),
        defaults.residentKey(),
        defaults.attestationConveyance(),
        defaults.counterRegression());
  }

  @Singleton
  ClockProvider clockProvider() {
    return ClockProvider.system();
  }

  @Singleton
  JwtConfig jwtConfig(PkAuthConfiguration config) {
    return JwtConfig.defaults(config.getJwt().getIssuer(), config.getJwt().getAudience());
  }

  @Singleton
  JwtKeyset jwtKeyset(PkAuthConfiguration config) {
    String secret = config.getJwt().getSecret();
    if (secret == null || secret.isBlank()) {
      throw new IllegalArgumentException(
          "pkauth.jwt.secret must be configured (≥ 32 bytes for HS256), or supply a JwtKeyset"
              + " bean. Silent fallback to a random one-shot key was removed because it breaks"
              + " multi-instance deployments and masks misconfiguration.");
    }
    byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
    if (bytes.length < 32) {
      throw new IllegalArgumentException(
          "pkauth.jwt.secret must be at least 32 bytes for HS256 (got "
              + bytes.length
              + "). Configure a ≥ 32-byte random value or supply a JwtKeyset bean.");
    }
    return JwtKeyset.hs256(bytes);
  }

  @Singleton
  PkAuthJwtIssuer jwtIssuer(JwtConfig cfg, JwtKeyset keyset, ClockProvider clock) {
    return new PkAuthJwtIssuer(cfg, keyset, clock);
  }

  @Singleton
  PkAuthJwtValidator jwtValidator(JwtConfig cfg, JwtKeyset keyset, ClockProvider clock) {
    return new PkAuthJwtValidator(cfg, keyset, clock);
  }

  @Singleton
  PasskeyAuthenticationService ceremonyService(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      ChallengeStore challengeStore,
      RelyingPartyConfig rp,
      CeremonyConfig ceremonyConfig,
      ClockProvider clock) {
    return PasskeyAuthenticationServices.builder()
        .credentialRepository(credentialRepository)
        .userLookup(userLookup)
        .challengeStore(challengeStore)
        .relyingPartyConfig(rp)
        .ceremonyConfig(ceremonyConfig)
        .clockProvider(clock)
        .build();
  }

  @Singleton
  BackupCodeService backupCodeService(BackupCodeRepository repo, ClockProvider clock) {
    return new BackupCodeService(repo, clock);
  }

  /**
   * Logging senders are dev-only: they write magic-link tokens / OTP codes to the application log.
   * They activate only when {@code pkauth.dev-mode=true}; otherwise a host must supply real {@code
   * EmailSender} / {@code SmsSender} beans.
   */
  @Singleton
  @Requires(property = "pkauth.dev-mode", value = "true")
  EmailSender emailSender() {
    LOG.error(
        "pkauth.dev-mode=true: using LoggingEmailSender — magic-link tokens will be written to"
            + " the application log. DO NOT use in production.");
    return new LoggingEmailSender();
  }

  @Singleton
  @Requires(property = "pkauth.dev-mode", value = "true")
  SmsSender smsSender() {
    LOG.error(
        "pkauth.dev-mode=true: using LoggingSmsSender — OTP codes will be written to the"
            + " application log. DO NOT use in production.");
    return new LoggingSmsSender();
  }

  @Singleton
  MagicLinkService magicLinkService(
      PkAuthJwtIssuer issuer,
      PkAuthJwtValidator validator,
      EmailSender emailSender,
      UserLookup userLookup,
      ClockProvider clock) {
    return new MagicLinkService(
        issuer, validator, emailSender, userLookup, clock, "http://localhost:8080/auth/magic");
  }

  @Singleton
  OtpService otpService(OtpRepository repo, SmsSender sms, ClockProvider clock) {
    // OtpService requires a pepper for hashing stored codes; generate a per-startup random pepper.
    // Host apps that need stable peppers across restarts declare their own OtpService bean.
    byte[] pepper = new byte[32];
    new java.security.SecureRandom().nextBytes(pepper);
    return new OtpService(repo, sms, clock, pepper);
  }

  @Singleton
  AdminService adminService(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      BackupCodeService backupCodeService,
      MagicLinkService magicLinkService,
      OtpService otpService) {
    return DefaultAdminService.builder()
        .credentialRepository(credentialRepository)
        .userLookup(userLookup)
        .backupCodeService(backupCodeService)
        .magicLinkService(magicLinkService)
        .otpService(otpService)
        .build();
  }
}
