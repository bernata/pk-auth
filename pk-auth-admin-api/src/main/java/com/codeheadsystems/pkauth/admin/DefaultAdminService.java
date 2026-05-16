// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService.ConsumeResult;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService.SendResult;
import com.codeheadsystems.pkauth.otp.OtpService;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Default {@link AdminService} composition over the Phase 5/6 SPIs and services. */
public final class DefaultAdminService implements AdminService {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultAdminService.class);

  private final CredentialRepository credentialRepository;
  private final UserLookup userLookup;
  private final BackupCodeService backupCodeService;
  private final MagicLinkService magicLinkService;
  private final OtpService otpService;
  private final AdminAuthorizer authorizer;
  private final AdminSafetyConfig safetyConfig;

  private DefaultAdminService(
      Dependencies deps, AdminAuthorizer authorizer, AdminSafetyConfig safetyConfig) {
    this.credentialRepository = deps.credentialRepository();
    this.userLookup = deps.userLookup();
    this.backupCodeService = deps.backupCodeService();
    this.magicLinkService = deps.magicLinkService();
    this.otpService = deps.otpService();
    this.authorizer = authorizer;
    this.safetyConfig = safetyConfig;
  }

  /**
   * Creates a {@link DefaultAdminService} with default {@link AdminAuthorizer} and {@link
   * AdminSafetyConfig}.
   */
  public static DefaultAdminService create(Dependencies deps) {
    return new DefaultAdminService(
        deps, AdminAuthorizer.subjectScoped(), AdminSafetyConfig.defaults());
  }

  /**
   * Creates a {@link DefaultAdminService} with a custom authorizer and default {@link
   * AdminSafetyConfig}.
   */
  public static DefaultAdminService create(Dependencies deps, AdminAuthorizer authorizer) {
    return new DefaultAdminService(deps, authorizer, AdminSafetyConfig.defaults());
  }

  /**
   * Creates a {@link DefaultAdminService} with a custom authorizer and custom {@link
   * AdminSafetyConfig}.
   */
  public static DefaultAdminService create(
      Dependencies deps, AdminAuthorizer authorizer, AdminSafetyConfig safetyConfig) {
    return new DefaultAdminService(deps, authorizer, safetyConfig);
  }

  // -- Account --

  @Override
  public AdminResult<AccountSummary> getAccount(UserHandle actor, UserHandle target) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    Optional<UserLookup.UserView> view = userLookup.findUserByHandle(target);
    if (view.isEmpty()) return new AdminResult.NotFound<>();
    int credentialCount = credentialRepository.findByUserHandle(target).size();
    int remaining = backupCodeService.remainingCount(target);
    UserLookup.UserView v = view.get();
    return new AdminResult.Success<>(
        new AccountSummary(
            v.handle(),
            v.username(),
            v.displayName(),
            v.emailVerified(),
            v.phoneVerified(),
            credentialCount,
            remaining));
  }

  // -- Credentials --

  @Override
  public AdminResult<List<CredentialSummary>> listCredentials(UserHandle actor, UserHandle target) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    List<CredentialSummary> credentials =
        credentialRepository.findByUserHandle(target).stream().map(CredentialSummary::of).toList();
    return new AdminResult.Success<>(credentials);
  }

  @Override
  public AdminResult<CredentialSummary> renameCredential(
      UserHandle actor, UserHandle target, CredentialId credentialId, String newLabel) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    if (newLabel == null || newLabel.isBlank()) {
      return new AdminResult.ValidationFailed<>("label must be non-blank");
    }
    Optional<CredentialRecord> cred = credentialRepository.findByCredentialId(credentialId);
    if (cred.isEmpty() || !cred.get().userHandle().equals(target)) {
      return new AdminResult.NotFound<>();
    }
    credentialRepository.updateLabel(credentialId, newLabel);
    CredentialRecord updated = credentialRepository.findByCredentialId(credentialId).orElseThrow();
    return new AdminResult.Success<>(CredentialSummary.of(updated));
  }

  @Override
  public AdminResult<Void> deleteCredential(
      UserHandle actor, UserHandle target, CredentialId credentialId) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    Optional<CredentialRecord> cred = credentialRepository.findByCredentialId(credentialId);
    if (cred.isEmpty() || !cred.get().userHandle().equals(target)) {
      return new AdminResult.NotFound<>();
    }
    if (!safetyConfig.allowDeleteWithoutBackupCodes()) {
      List<CredentialRecord> all = credentialRepository.findByUserHandle(target);
      boolean lastOne = all.size() == 1 && all.get(0).credentialId().equals(credentialId);
      if (lastOne && backupCodeService.remainingCount(target) == 0) {
        return new AdminResult.Conflict<>(
            "Cannot delete the last credential while no backup codes remain.");
      }
    }
    credentialRepository.delete(credentialId);
    return new AdminResult.Success<>(null);
  }

  // -- Backup codes --

  @Override
  public AdminResult<BackupCodesGenerated> regenerateBackupCodes(
      UserHandle actor, UserHandle target) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    List<String> plaintext = backupCodeService.regenerateAll(target);
    return new AdminResult.Success<>(new BackupCodesGenerated(plaintext));
  }

  @Override
  public AdminResult<Integer> remainingBackupCodes(UserHandle actor, UserHandle target) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    return new AdminResult.Success<>(backupCodeService.remainingCount(target));
  }

  // -- Email --

  @Override
  public AdminResult<Void> startEmailVerification(
      UserHandle actor, UserHandle target, String email) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    if (email == null || email.isBlank()) {
      return new AdminResult.ValidationFailed<>("email must be non-blank");
    }
    SendResult send = magicLinkService.sendVerificationEmail(target, email);
    if (send instanceof SendResult.RateLimited) {
      return new AdminResult.RateLimited<>(Duration.ofHours(1));
    }
    if (send instanceof SendResult.EmailMismatch) {
      return new AdminResult.ValidationFailed<>(
          "email does not match the address bound to this user");
    }
    return new AdminResult.Success<>(null);
  }

  @Override
  public AdminResult<UserHandle> completeEmailVerification(String token) {
    if (token == null || token.isBlank()) {
      return new AdminResult.ValidationFailed<>("token must be non-blank");
    }
    ConsumeResult result = magicLinkService.consume(token);
    if (result instanceof ConsumeResult.Success success) {
      // Host apps own the users table; we report success and let the adapter persist the
      // emailVerified flag via UserLookup's host-app-specific update path (out of scope here).
      LOG.info("admin.email.verified user={}", success.userHandle());
      return new AdminResult.Success<>(success.userHandle());
    }
    if (result instanceof ConsumeResult.AlreadyConsumed) {
      return new AdminResult.Conflict<>("token already consumed");
    }
    return new AdminResult.ValidationFailed<>("invalid token");
  }

  // -- Phone --

  @Override
  public AdminResult<OtpDispatchResult> startPhoneVerification(
      UserHandle actor, UserHandle target, String phoneE164) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    if (phoneE164 == null || !phoneE164.startsWith("+")) {
      return new AdminResult.ValidationFailed<>("phone must be E.164 format");
    }
    OtpService.SendResult send = otpService.send(target, phoneE164);
    if (send instanceof OtpService.SendResult.RateLimited) {
      return new AdminResult.RateLimited<>(Duration.ofMinutes(15));
    }
    return new AdminResult.Success<>(
        new OtpDispatchResult(((OtpService.SendResult.Sent) send).otpId()));
  }

  @Override
  public AdminResult<PhoneVerificationResult> completePhoneVerification(
      UserHandle actor, UserHandle target, String phoneE164, String code) {
    if (!authorize(actor, target)) return new AdminResult.Forbidden<>();
    if (phoneE164 == null || code == null) {
      return new AdminResult.ValidationFailed<>("phone and code are required");
    }
    OtpService.VerifyResult result = otpService.verify(target, phoneE164, code);
    return new AdminResult.Success<>(
        switch (result) {
          case OtpService.VerifyResult.Success s -> new PhoneVerificationResult.Verified();
          case OtpService.VerifyResult.NoActiveOtp n -> new PhoneVerificationResult.Expired();
          case OtpService.VerifyResult.Expired e -> new PhoneVerificationResult.Expired();
          case OtpService.VerifyResult.AttemptsExceeded a ->
              new PhoneVerificationResult.AttemptsExceeded();
          case OtpService.VerifyResult.CodeMismatch m ->
              new PhoneVerificationResult.Mismatch(m.remainingAttempts());
        });
  }

  // -- helpers --

  private boolean authorize(UserHandle actor, UserHandle target) {
    Objects.requireNonNull(actor, "actor");
    Objects.requireNonNull(target, "target");
    return authorizer.canAct(actor, target);
  }

  /**
   * Canonical holder of the five required collaborators for {@link DefaultAdminService}.
   *
   * <p>Pass an instance to {@link #create(Dependencies)} (or the overloads that accept an optional
   * {@link AdminAuthorizer} / {@link AdminSafetyConfig}) to construct a service. Using a record
   * keeps construction sites concise and self-documenting through Java's named component syntax.
   */
  public record Dependencies(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      BackupCodeService backupCodeService,
      MagicLinkService magicLinkService,
      OtpService otpService) {
    /** Compact constructor — enforces non-null on all required collaborators. */
    public Dependencies {
      Objects.requireNonNull(credentialRepository, "credentialRepository");
      Objects.requireNonNull(userLookup, "userLookup");
      Objects.requireNonNull(backupCodeService, "backupCodeService");
      Objects.requireNonNull(magicLinkService, "magicLinkService");
      Objects.requireNonNull(otpService, "otpService");
    }
  }
}
