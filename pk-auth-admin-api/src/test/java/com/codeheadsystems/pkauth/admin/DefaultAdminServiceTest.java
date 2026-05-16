// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.jwt.JwtKeyset;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.magiclink.LoggingEmailSender;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService;
import com.codeheadsystems.pkauth.otp.LoggingSmsSender;
import com.codeheadsystems.pkauth.otp.OtpService;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryBackupCodeRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryCredentialRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryOtpRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryUserLookup;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DefaultAdminServiceTest {

  private static final Instant NOW = Instant.parse("2026-05-14T12:00:00Z");
  private static final ClockProvider CLOCK =
      ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC));

  private InMemoryUserLookup users;
  private InMemoryCredentialRepository credentials;
  private InMemoryBackupCodeRepository backupCodes;
  private InMemoryOtpRepository otpRepo;
  private MagicLinkService magicLink;
  private BackupCodeService backupCodeService;
  private OtpService otpService;
  private DefaultAdminService admin;
  private UserHandle alice;

  @BeforeEach
  void setUp() {
    users = new InMemoryUserLookup();
    credentials = new InMemoryCredentialRepository();
    backupCodes = new InMemoryBackupCodeRepository();
    otpRepo = new InMemoryOtpRepository();

    alice = users.register("alice", "Alice");

    Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    byte[] otpPepper = new byte[32];
    new SecureRandom().nextBytes(otpPepper);
    backupCodeService =
        BackupCodeService.create(
            BackupCodeService.Dependencies.of(backupCodes, CLOCK),
            new BackupCodeService.Config(
                new SecureRandom(),
                argon2,
                /* iterations */ 1,
                /* memory */ 1024,
                /* parallelism */ 1,
                /* codeCount */ 5,
                /* rateLimit */ BackupCodeService.DEFAULT_RATE_LIMIT));
    otpService =
        OtpService.create(
            OtpService.Dependencies.of(otpRepo, new LoggingSmsSender(), CLOCK),
            new OtpService.Config(
                new SecureRandom(),
                otpPepper,
                Duration.ofMinutes(5),
                3,
                3,
                Duration.ofMinutes(15)));

    byte[] secret = new byte[32];
    new SecureRandom().nextBytes(secret);
    JwtKeyset keyset = JwtKeyset.hs256(secret);
    JwtConfig jwtConfig =
        JwtConfig.defaults("https://pkauth.example.com", "https://app.example.com");
    magicLink =
        MagicLinkService.create(
            MagicLinkService.Dependencies.of(
                new PkAuthJwtIssuer(jwtConfig, keyset, CLOCK),
                new PkAuthJwtValidator(jwtConfig, keyset, CLOCK),
                new LoggingEmailSender(),
                users,
                CLOCK),
            "https://app.example.com/auth/magic");

    admin =
        DefaultAdminService.create(
            new DefaultAdminService.Dependencies(
                credentials, users, backupCodeService, magicLink, otpService));
  }

  // -- Account --

  @Test
  void getAccountReturnsCorrectShape() {
    saveCredential(alice, new byte[] {1});
    backupCodeService.generate(alice);

    AdminResult<AccountSummary> result = admin.getAccount(alice, alice);
    assertThat(result)
        .isInstanceOfSatisfying(
            AdminResult.Success.class,
            s -> {
              AccountSummary summary = (AccountSummary) s.value();
              assertThat(summary.username()).isEqualTo("alice");
              assertThat(summary.credentialCount()).isEqualTo(1);
              assertThat(summary.remainingBackupCodes()).isEqualTo(5);
            });
  }

  @Test
  void getAccountForbiddenWhenActorMismatch() {
    UserHandle bob = users.register("bob", "Bob");
    assertThat(admin.getAccount(alice, bob)).isInstanceOf(AdminResult.Forbidden.class);
  }

  @Test
  void getAccountNotFoundWhenUserAbsent() {
    UserHandle ghost = UserHandle.random();
    assertThat(admin.getAccount(ghost, ghost)).isInstanceOf(AdminResult.NotFound.class);
  }

  // -- Credentials --

  @Test
  void listCredentialsReturnsAllForUser() {
    saveCredential(alice, new byte[] {1});
    saveCredential(alice, new byte[] {2});
    AdminResult<List<CredentialSummary>> result = admin.listCredentials(alice, alice);
    @SuppressWarnings("unchecked")
    AdminResult.Success<List<CredentialSummary>> success =
        (AdminResult.Success<List<CredentialSummary>>) result;
    assertThat(success.value()).hasSize(2);
  }

  @Test
  void renameCredentialUpdatesLabel() {
    saveCredential(alice, new byte[] {1});
    AdminResult<CredentialSummary> result =
        admin.renameCredential(alice, alice, CredentialId.of(new byte[] {1}), "Work key");
    assertThat(result)
        .isInstanceOfSatisfying(
            AdminResult.Success.class,
            s -> assertThat(((CredentialSummary) s.value()).label()).isEqualTo("Work key"));
  }

  @Test
  void renameCredentialBlankLabelRejected() {
    saveCredential(alice, new byte[] {1});
    assertThat(admin.renameCredential(alice, alice, CredentialId.of(new byte[] {1}), " "))
        .isInstanceOf(AdminResult.ValidationFailed.class);
  }

  @Test
  void renameCredentialOfOtherUserNotFound() {
    UserHandle bob = users.register("bob", "Bob");
    saveCredential(bob, new byte[] {1});
    AdminResult<CredentialSummary> result =
        admin.renameCredential(bob, bob, CredentialId.of(new byte[] {1}), "newlabel");
    assertThat(result).isInstanceOf(AdminResult.Success.class);
    // alice tries to rename bob's credential — authorizer denies before NotFound check.
    assertThat(admin.renameCredential(alice, bob, CredentialId.of(new byte[] {1}), "x"))
        .isInstanceOf(AdminResult.Forbidden.class);
  }

  @Test
  void deleteLastCredentialWithoutBackupCodesIsConflict() {
    saveCredential(alice, new byte[] {1});
    assertThat(admin.deleteCredential(alice, alice, CredentialId.of(new byte[] {1})))
        .isInstanceOf(AdminResult.Conflict.class);
    assertThat(credentials.findByCredentialId(CredentialId.of(new byte[] {1}))).isPresent();
  }

  @Test
  void deleteLastCredentialWithBackupCodesSucceeds() {
    saveCredential(alice, new byte[] {1});
    backupCodeService.generate(alice);
    assertThat(admin.deleteCredential(alice, alice, CredentialId.of(new byte[] {1})))
        .isInstanceOf(AdminResult.Success.class);
    assertThat(credentials.findByCredentialId(CredentialId.of(new byte[] {1}))).isEmpty();
  }

  @Test
  void deleteLastCredentialAllowedWhenSafetyOff() {
    DefaultAdminService unsafe =
        DefaultAdminService.create(
            new DefaultAdminService.Dependencies(
                credentials, users, backupCodeService, magicLink, otpService),
            new DefaultAdminService.Config(
                AdminAuthorizer.subjectScoped(), new AdminSafetyConfig(true)));
    saveCredential(alice, new byte[] {1});
    assertThat(unsafe.deleteCredential(alice, alice, CredentialId.of(new byte[] {1})))
        .isInstanceOf(AdminResult.Success.class);
  }

  @Test
  void deleteUnknownCredentialNotFound() {
    assertThat(admin.deleteCredential(alice, alice, CredentialId.of(new byte[] {99})))
        .isInstanceOf(AdminResult.NotFound.class);
  }

  // -- Backup codes --

  @Test
  void regenerateBackupCodesReturnsPlaintextAndPersists() {
    AdminResult<BackupCodesGenerated> result = admin.regenerateBackupCodes(alice, alice);
    assertThat(result)
        .isInstanceOfSatisfying(
            AdminResult.Success.class,
            s -> assertThat(((BackupCodesGenerated) s.value()).codes()).hasSize(5));
    assertThat(backupCodeService.remainingCount(alice)).isEqualTo(5);
  }

  @Test
  void remainingBackupCodesCount() {
    backupCodeService.generate(alice);
    assertThat(admin.remainingBackupCodes(alice, alice))
        .isInstanceOfSatisfying(AdminResult.Success.class, s -> assertThat(s.value()).isEqualTo(5));
  }

  // -- Email verification --

  @Test
  void startEmailVerificationDispatches() {
    assertThat(admin.startEmailVerification(alice, alice, "alice@example.com"))
        .isInstanceOf(AdminResult.Success.class);
  }

  @Test
  void startEmailVerificationBlankRejected() {
    assertThat(admin.startEmailVerification(alice, alice, ""))
        .isInstanceOf(AdminResult.ValidationFailed.class);
  }

  @Test
  void finishEmailVerificationConsumesToken() {
    MagicLinkService.SendResult send = magicLink.startEmailVerification(alice, "alice@example.com");
    String token = ((MagicLinkService.SendResult.Sent) send).tokenJti();
    AdminResult<UserHandle> result = admin.finishEmailVerification(token);
    assertThat(result)
        .isInstanceOfSatisfying(
            AdminResult.Success.class, s -> assertThat(s.value()).isEqualTo(alice));

    // Second consume → Conflict.
    assertThat(admin.finishEmailVerification(token)).isInstanceOf(AdminResult.Conflict.class);
  }

  @Test
  void finishEmailVerificationInvalidToken() {
    assertThat(admin.finishEmailVerification("not.a.jwt"))
        .isInstanceOf(AdminResult.ValidationFailed.class);
  }

  // -- Phone verification --

  @Test
  void startPhoneVerificationDispatches() {
    AdminResult<OtpDispatchResult> result =
        admin.startPhoneVerification(alice, alice, "+15551234567");
    assertThat(result).isInstanceOf(AdminResult.Success.class);
  }

  @Test
  void startPhoneVerificationNonE164Rejected() {
    assertThat(admin.startPhoneVerification(alice, alice, "5551234567"))
        .isInstanceOf(AdminResult.ValidationFailed.class);
  }

  @Test
  void startPhoneVerificationRateLimited() {
    admin.startPhoneVerification(alice, alice, "+15551234567");
    admin.startPhoneVerification(alice, alice, "+15551234567");
    admin.startPhoneVerification(alice, alice, "+15551234567");
    assertThat(admin.startPhoneVerification(alice, alice, "+15551234567"))
        .isInstanceOf(AdminResult.RateLimited.class);
  }

  @Test
  void finishPhoneVerificationFlow() {
    AdminResult<PhoneVerificationResult> miss =
        admin.finishPhoneVerification(alice, alice, "+15551234567", "000000");
    assertThat(miss)
        .isInstanceOfSatisfying(
            AdminResult.Success.class,
            s -> assertThat(s.value()).isInstanceOf(PhoneVerificationResult.Expired.class));
  }

  // -- Authorizer override --

  @Test
  void supportStaffAuthorizerOverride() {
    UserHandle support = users.register("support", "Support");
    DefaultAdminService delegating =
        DefaultAdminService.create(
            new DefaultAdminService.Dependencies(
                credentials, users, backupCodeService, magicLink, otpService),
            new DefaultAdminService.Config(
                (actor, target) -> actor.equals(support) || actor.equals(target),
                AdminSafetyConfig.defaults()));
    assertThat(delegating.getAccount(support, alice)).isInstanceOf(AdminResult.Success.class);
  }

  // -- Dependencies record --

  @Test
  void dependenciesRejectsNullInputs() {
    org.junit.jupiter.api.Assertions.assertAll(
        () ->
            org.junit.jupiter.api.Assertions.assertThrows(
                NullPointerException.class,
                () ->
                    new DefaultAdminService.Dependencies(
                        null, users, backupCodeService, magicLink, otpService)),
        () ->
            org.junit.jupiter.api.Assertions.assertThrows(
                NullPointerException.class,
                () ->
                    new DefaultAdminService.Dependencies(
                        credentials, null, backupCodeService, magicLink, otpService)),
        () ->
            org.junit.jupiter.api.Assertions.assertThrows(
                NullPointerException.class,
                () ->
                    new DefaultAdminService.Dependencies(
                        credentials, users, null, magicLink, otpService)),
        () ->
            org.junit.jupiter.api.Assertions.assertThrows(
                NullPointerException.class,
                () ->
                    new DefaultAdminService.Dependencies(
                        credentials, users, backupCodeService, null, otpService)),
        () ->
            org.junit.jupiter.api.Assertions.assertThrows(
                NullPointerException.class,
                () ->
                    new DefaultAdminService.Dependencies(
                        credentials, users, backupCodeService, magicLink, null)));
  }

  // -- helpers --

  private CredentialRecord saveCredential(UserHandle user, byte[] credentialId) {
    CredentialRecord record =
        new CredentialRecord(
            CredentialId.of(credentialId),
            user,
            new byte[] {0x10},
            0L,
            "Test",
            null,
            Set.of(Transport.USB),
            true,
            true,
            NOW,
            null);
    credentials.save(record);
    return record;
  }

  /** Keeps unused-import warnings down without removing the import. */
  @SuppressWarnings("unused")
  private CredentialRepository requireRepo() {
    return credentials;
  }
}
