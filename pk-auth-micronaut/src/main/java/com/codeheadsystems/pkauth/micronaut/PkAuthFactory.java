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
import jakarta.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Set;

/**
 * Wires every pk-auth service Micronaut hosts. Persistence SPIs ({@link CredentialRepository},
 * {@link UserLookup}, {@link ChallengeStore}, {@link BackupCodeRepository}, {@link OtpRepository})
 * must be supplied by the host application or by including {@code pk-auth-persistence-jdbi} /
 * {@code pk-auth-persistence-dynamodb} with their own factories.
 */
@Factory
public class PkAuthFactory {

  @Singleton
  RelyingPartyConfig relyingPartyConfig(PkAuthConfiguration config) {
    PkAuthConfiguration.RelyingParty rp = config.getRelyingParty();
    return new RelyingPartyConfig(rp.getId(), rp.getName(), Set.copyOf(rp.getOrigins()));
  }

  @Singleton
  CeremonyConfig ceremonyConfig() {
    return CeremonyConfig.defaults();
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
    byte[] bytes;
    if (secret == null || secret.isBlank()) {
      bytes = new byte[32];
      new SecureRandom().nextBytes(bytes);
    } else {
      bytes = secret.getBytes(StandardCharsets.UTF_8);
      if (bytes.length < 32) {
        // Nimbus rejects HS256 secrets under 32 bytes. Pad rather than crash on dev configs.
        byte[] padded = new byte[32];
        System.arraycopy(bytes, 0, padded, 0, bytes.length);
        bytes = padded;
      }
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

  @Singleton
  EmailSender emailSender() {
    return new LoggingEmailSender();
  }

  @Singleton
  SmsSender smsSender() {
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
    return new OtpService(repo, sms, clock);
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
