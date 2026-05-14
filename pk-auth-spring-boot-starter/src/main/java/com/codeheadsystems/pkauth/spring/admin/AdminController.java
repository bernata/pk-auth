// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.admin;

import com.codeheadsystems.pkauth.admin.AdminResult;
import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spring.security.JwtAuthenticationToken;
import java.util.Map;
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
 * JwtAuthenticationToken} in {@link SecurityContextHolder}. The brief's authorization model is
 * subject-scoped: the actor must equal the target. The actor passes themselves as the target on
 * every call — host apps wanting staff-impersonation flows wire a non-default {@code
 * AdminAuthorizer} bean and add their own {@code target} route segment.
 */
@RestController
@RequestMapping("/auth/admin")
public class AdminController {

  private final AdminService adminService;

  public AdminController(AdminService adminService) {
    this.adminService = adminService;
  }

  // -- Account ---------------------------------------------------------------------------------

  @GetMapping("/account")
  public ResponseEntity<Object> account() {
    UserHandle user = currentUser();
    return AdminResultMapper.toResponse(adminService.getAccount(user, user));
  }

  // -- Credentials -----------------------------------------------------------------------------

  @GetMapping("/credentials")
  public ResponseEntity<Object> listCredentials() {
    UserHandle user = currentUser();
    return AdminResultMapper.toResponse(adminService.listCredentials(user, user));
  }

  @PatchMapping("/credentials/{credentialId}")
  public ResponseEntity<Object> rename(
      @PathVariable("credentialId") String credentialId, @RequestBody RenameBody body) {
    UserHandle user = currentUser();
    byte[] id = Base64Url.decode(credentialId);
    return AdminResultMapper.toResponse(
        adminService.renameCredential(user, user, id, body == null ? "" : body.label()));
  }

  @DeleteMapping("/credentials/{credentialId}")
  public ResponseEntity<Object> delete(@PathVariable("credentialId") String credentialId) {
    UserHandle user = currentUser();
    byte[] id = Base64Url.decode(credentialId);
    AdminResult<Void> result = adminService.deleteCredential(user, user, id);
    return AdminResultMapper.toEmptyResponse(result);
  }

  // -- Backup codes ----------------------------------------------------------------------------

  @PostMapping("/backup-codes/regenerate")
  public ResponseEntity<Object> regenerateBackupCodes() {
    UserHandle user = currentUser();
    return AdminResultMapper.toResponse(adminService.regenerateBackupCodes(user, user));
  }

  @GetMapping("/backup-codes/count")
  public ResponseEntity<Object> remainingBackupCodes() {
    UserHandle user = currentUser();
    AdminResult<Integer> result = adminService.remainingBackupCodes(user, user);
    return switch (result) {
      case AdminResult.Success<Integer> s -> ResponseEntity.ok(Map.of("remaining", s.value()));
      default -> AdminResultMapper.toResponse(result);
    };
  }

  // -- Email -----------------------------------------------------------------------------------

  @PostMapping("/email/start-verification")
  public ResponseEntity<Object> startEmailVerification(@RequestBody EmailBody body) {
    UserHandle user = currentUser();
    AdminResult<Void> result =
        adminService.startEmailVerification(user, user, body == null ? "" : body.email());
    return AdminResultMapper.toEmptyResponse(result);
  }

  /** Unauthenticated per brief §6.9 ("token identifies the user"). */
  @PostMapping("/email/complete-verification")
  public ResponseEntity<Object> completeEmailVerification(@RequestBody TokenBody body) {
    AdminResult<UserHandle> result =
        adminService.completeEmailVerification(body == null ? "" : body.token());
    return switch (result) {
      case AdminResult.Success<UserHandle> s ->
          ResponseEntity.ok(Map.of("userHandle", Base64Url.encode(s.value().value())));
      default -> AdminResultMapper.toResponse(result);
    };
  }

  // -- Phone -----------------------------------------------------------------------------------

  @PostMapping("/phone/start-verification")
  public ResponseEntity<Object> startPhoneVerification(@RequestBody PhoneBody body) {
    UserHandle user = currentUser();
    return AdminResultMapper.toResponse(
        adminService.startPhoneVerification(user, user, body == null ? "" : body.phone()));
  }

  @PostMapping("/phone/complete-verification")
  public ResponseEntity<Object> completePhoneVerification(@RequestBody PhoneVerifyBody body) {
    UserHandle user = currentUser();
    return AdminResultMapper.toResponse(
        adminService.completePhoneVerification(
            user, user, body == null ? "" : body.phone(), body == null ? "" : body.code()));
  }

  // -- helpers ---------------------------------------------------------------------------------

  private UserHandle currentUser() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof JwtAuthenticationToken pkAuthToken && pkAuthToken.isAuthenticated()) {
      return pkAuthToken.getPrincipal();
    }
    throw new AccessDeniedException("Authenticated pk-auth JWT required");
  }

  /** Body for credential rename. */
  public record RenameBody(String label) {}

  /** Body for email verification start. */
  public record EmailBody(String email) {}

  /** Body for email verification complete. */
  public record TokenBody(String token) {}

  /** Body for phone verification start. */
  public record PhoneBody(String phone) {}

  /** Body for phone verification complete. */
  public record PhoneVerifyBody(String phone, String code) {}
}
