// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.admin;

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
import com.codeheadsystems.pkauth.dropwizard.auth.PkAuthPasskeyPrincipal;
import com.codeheadsystems.pkauth.json.Base64Url;
import io.dropwizard.auth.Auth;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Objects;

/**
 * HTTP exposure of {@link AdminService}. Mounted at {@code /auth/admin} by the bundle when {@code
 * pk-auth-admin-api} is on the classpath. All endpoints except {@code complete-verification}
 * require authentication; subject-scoping is enforced by {@link AdminService}'s configured {@link
 * com.codeheadsystems.pkauth.admin.AdminAuthorizer}.
 *
 * <p>Request bodies are the shared records on {@link
 * com.codeheadsystems.pkauth.admin.AdminRequests} and responses use the shared {@link
 * BackupCodesCountResponse} and {@link EmailVerificationResult} records so every adapter emits
 * byte-for-byte identical JSON.
 *
 * @since 0.9.1
 */
@Path("/auth/admin")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class PkAuthAdminResource {

  private final AdminService adminService;

  @Inject
  public PkAuthAdminResource(AdminService adminService) {
    this.adminService = Objects.requireNonNull(adminService, "adminService");
  }

  @GET
  @Path("/account")
  public Response getAccount(@Auth PkAuthPasskeyPrincipal principal) {
    UserHandle user = principal.userHandle();
    return PkAuthAdminResultMapper.toResponse(adminService.getAccount(user, user));
  }

  @GET
  @Path("/credentials")
  public Response listCredentials(@Auth PkAuthPasskeyPrincipal principal) {
    UserHandle user = principal.userHandle();
    return PkAuthAdminResultMapper.toResponse(adminService.listCredentials(user, user));
  }

  @PATCH
  @Path("/credentials/{credentialId}")
  public Response renameCredential(
      @Auth PkAuthPasskeyPrincipal principal,
      @PathParam("credentialId") String credentialIdB64Url,
      RenameCredential body) {
    UserHandle user = principal.userHandle();
    CredentialId id = CredentialId.fromB64Url(credentialIdB64Url);
    String label = body == null ? null : body.label();
    AdminResult<?> result = adminService.renameCredential(user, user, id, label);
    return PkAuthAdminResultMapper.toResponse(result);
  }

  @DELETE
  @Path("/credentials/{credentialId}")
  public Response deleteCredential(
      @Auth PkAuthPasskeyPrincipal principal,
      @PathParam("credentialId") String credentialIdB64Url) {
    UserHandle user = principal.userHandle();
    CredentialId id = CredentialId.fromB64Url(credentialIdB64Url);
    return PkAuthAdminResultMapper.toResponse(adminService.deleteCredential(user, user, id));
  }

  @POST
  @Path("/backup-codes/regenerate")
  public Response regenerateBackupCodes(@Auth PkAuthPasskeyPrincipal principal) {
    UserHandle user = principal.userHandle();
    return PkAuthAdminResultMapper.toResponse(adminService.regenerateBackupCodes(user, user));
  }

  @GET
  @Path("/backup-codes/count")
  public Response remainingBackupCodes(@Auth PkAuthPasskeyPrincipal principal) {
    UserHandle user = principal.userHandle();
    AdminResult<Integer> result = adminService.remainingBackupCodes(user, user);
    return switch (result) {
      case AdminResult.Success<Integer> s ->
          Response.ok(new BackupCodesCountResponse(s.value())).build();
      default -> PkAuthAdminResultMapper.toResponse(result);
    };
  }

  @POST
  @Path("/email/start-verification")
  public Response startEmailVerification(
      @Auth PkAuthPasskeyPrincipal principal, StartEmailVerification body) {
    UserHandle user = principal.userHandle();
    String email = body == null ? null : body.email();
    return PkAuthAdminResultMapper.toResponse(
        adminService.startEmailVerification(user, user, email));
  }

  /** Brief §6.9 mounts the complete-verification endpoint as unauthenticated. */
  @POST
  @Path("/email/complete-verification")
  public Response completeEmailVerification(FinishEmailVerification body) {
    String token = body == null ? null : body.token();
    AdminResult<UserHandle> result = adminService.completeEmailVerification(token);
    return switch (result) {
      case AdminResult.Success<UserHandle> s ->
          Response.ok(new EmailVerificationResult(Base64Url.encode(s.value().value()))).build();
      default -> PkAuthAdminResultMapper.toResponse(result);
    };
  }

  @POST
  @Path("/phone/start-verification")
  public Response startPhoneVerification(
      @Auth PkAuthPasskeyPrincipal principal, StartPhoneVerification body) {
    UserHandle user = principal.userHandle();
    String phone = body == null ? null : body.phone();
    return PkAuthAdminResultMapper.toResponse(
        adminService.startPhoneVerification(user, user, phone));
  }

  @POST
  @Path("/phone/complete-verification")
  public Response completePhoneVerification(
      @Auth PkAuthPasskeyPrincipal principal, FinishPhoneVerification body) {
    UserHandle user = principal.userHandle();
    String phone = body == null ? null : body.phone();
    String code = body == null ? null : body.code();
    return PkAuthAdminResultMapper.toResponse(
        adminService.completePhoneVerification(user, user, phone, code));
  }
}
