// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.admin;

import com.codeheadsystems.pkauth.admin.AdminRequests.FinishEmailVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.FinishPhoneVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.RenameCredential;
import com.codeheadsystems.pkauth.admin.AdminRequests.StartEmailVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.StartPhoneVerification;
import com.codeheadsystems.pkauth.admin.AdminResult;
import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.admin.BackupCodesCountResponse;
import com.codeheadsystems.pkauth.admin.EmailVerificationResult;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spring.security.PkAuthJwtAuthenticationToken;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST adapter for {@link AdminService}. Mounted under {@code /auth/admin} per brief §6.9 endpoint
 * table.
 *
 * <p>Every authenticated endpoint resolves the actor from the JWT-derived {@link
 * PkAuthJwtAuthenticationToken} in {@link SecurityContextHolder}. The brief's authorization model
 * is subject-scoped: the actor must equal the target. The actor passes themselves as the target on
 * every call — host apps wanting staff-impersonation flows wire a non-default {@code
 * AdminAuthorizer} bean and add their own {@code target} route segment.
 *
 * <p>Request bodies are the shared records on {@link
 * com.codeheadsystems.pkauth.admin.AdminRequests} and responses use the shared {@link
 * BackupCodesCountResponse} and {@link EmailVerificationResult} records so every adapter emits
 * byte-for-byte identical JSON.
 *
 * @since 0.9.1
 */
@RestController
@RequestMapping("/auth/admin")
public class PkAuthAdminController {

  private final AdminService adminService;

  public PkAuthAdminController(AdminService adminService) {
    this.adminService = adminService;
  }

  // -- Account ---------------------------------------------------------------------------------

  @GetMapping("/account")
  public ResponseEntity<Object> account() {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponse(adminService.getAccount(user, user));
  }

  // -- Credentials -----------------------------------------------------------------------------

  @GetMapping("/credentials")
  public ResponseEntity<Object> listCredentials() {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponse(adminService.listCredentials(user, user));
  }

  @PatchMapping("/credentials/{credentialId}")
  public ResponseEntity<Object> rename(
      @PathVariable("credentialId") String credentialId, @RequestBody RenameCredential body) {
    UserHandle user = currentUser();
    CredentialId id = CredentialId.fromB64Url(credentialId);
    return PkAuthAdminResultMapper.toResponse(
        adminService.renameCredential(user, user, id, body == null ? "" : body.label()));
  }

  @DeleteMapping("/credentials/{credentialId}")
  public ResponseEntity<Object> delete(@PathVariable("credentialId") String credentialId) {
    UserHandle user = currentUser();
    CredentialId id = CredentialId.fromB64Url(credentialId);
    return PkAuthAdminResultMapper.toResponse(adminService.deleteCredential(user, user, id));
  }

  // -- Backup codes ----------------------------------------------------------------------------

  @PostMapping("/backup-codes/regenerate")
  public ResponseEntity<Object> regenerateBackupCodes() {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponse(adminService.regenerateBackupCodes(user, user));
  }

  @GetMapping("/backup-codes/count")
  public ResponseEntity<Object> remainingBackupCodes() {
    UserHandle user = currentUser();
    AdminResult<Integer> result = adminService.remainingBackupCodes(user, user);
    return switch (result) {
      case AdminResult.Success<Integer> s ->
          ResponseEntity.ok(new BackupCodesCountResponse(s.value()));
      default -> PkAuthAdminResultMapper.toResponse(result);
    };
  }

  // -- Email -----------------------------------------------------------------------------------

  @PostMapping("/email/start-verification")
  public ResponseEntity<Object> startEmailVerification(@RequestBody StartEmailVerification body) {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponse(
        adminService.startEmailVerification(user, user, body == null ? "" : body.email()));
  }

  /** Unauthenticated per brief §6.9 ("token identifies the user"). */
  @PostMapping("/email/complete-verification")
  public ResponseEntity<Object> completeEmailVerification(
      @RequestBody FinishEmailVerification body) {
    AdminResult<UserHandle> result =
        adminService.completeEmailVerification(body == null ? "" : body.token());
    return switch (result) {
      case AdminResult.Success<UserHandle> s ->
          ResponseEntity.ok(new EmailVerificationResult(Base64Url.encode(s.value().value())));
      default -> PkAuthAdminResultMapper.toResponse(result);
    };
  }

  // -- Phone -----------------------------------------------------------------------------------

  @PostMapping("/phone/start-verification")
  public ResponseEntity<Object> startPhoneVerification(@RequestBody StartPhoneVerification body) {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponse(
        adminService.startPhoneVerification(user, user, body == null ? "" : body.phone()));
  }

  @PostMapping("/phone/complete-verification")
  public ResponseEntity<Object> completePhoneVerification(
      @RequestBody FinishPhoneVerification body) {
    UserHandle user = currentUser();
    return PkAuthAdminResultMapper.toResponse(
        adminService.completePhoneVerification(
            user, user, body == null ? "" : body.phone(), body == null ? "" : body.code()));
  }

  // -- helpers ---------------------------------------------------------------------------------

  private UserHandle currentUser() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof PkAuthJwtAuthenticationToken pkAuthToken && pkAuthToken.isAuthenticated()) {
      return pkAuthToken.getPrincipal();
    }
    throw new AccessDeniedException("Authenticated pk-auth JWT required");
  }
}
