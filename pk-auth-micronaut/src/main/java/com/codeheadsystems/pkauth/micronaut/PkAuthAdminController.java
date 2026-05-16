// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.admin.AccountSummary;
import com.codeheadsystems.pkauth.admin.AdminRequests.FinishEmailVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.FinishPhoneVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.RenameCredential;
import com.codeheadsystems.pkauth.admin.AdminRequests.StartEmailVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.StartPhoneVerification;
import com.codeheadsystems.pkauth.admin.AdminResponseMapper;
import com.codeheadsystems.pkauth.admin.AdminResponseMapper.AdminResponse;
import com.codeheadsystems.pkauth.admin.AdminResult;
import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.admin.BackupCodesCountResponse;
import com.codeheadsystems.pkauth.admin.BackupCodesGenerated;
import com.codeheadsystems.pkauth.admin.CredentialSummary;
import com.codeheadsystems.pkauth.admin.EmailVerificationResult;
import com.codeheadsystems.pkauth.admin.OtpDispatchResult;
import com.codeheadsystems.pkauth.admin.PhoneVerificationResult;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.UserHandle;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Patch;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import java.util.List;

/**
 * Admin controller mounting the brief §6.9 endpoints under {@code /auth/admin/**}. All
 * authenticated endpoints require the {@link PkAuthJwtAuthenticationFilter} to have attached a user
 * handle to the request; {@code complete-email-verification} is intentionally unauthenticated.
 *
 * <p>Every {@link AdminResult} is routed through {@link AdminResponseMapper} so the JSON shape is
 * byte-for-byte identical across the Spring, Dropwizard, and Micronaut adapters.
 *
 * @since 0.9.1
 */
@Controller("/auth/admin")
@Produces(MediaType.APPLICATION_JSON)
@ExecuteOn(TaskExecutors.BLOCKING)
public class PkAuthAdminController {

  private final AdminService adminService;

  public PkAuthAdminController(AdminService adminService) {
    this.adminService = adminService;
  }

  @Get("/account")
  public HttpResponse<?> account(HttpRequest<?> request) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return map(adminService.getAccount(actor, actor));
  }

  @Get("/credentials")
  public HttpResponse<?> listCredentials(HttpRequest<?> request) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return map(adminService.listCredentials(actor, actor));
  }

  /** Renames the credential identified by its base64url-encoded id. */
  @Patch("/credentials/{credentialId}")
  public HttpResponse<?> renameCredential(
      HttpRequest<?> request, @PathVariable String credentialId, @Body RenameCredential body) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    CredentialId id = CredentialId.fromB64Url(credentialId);
    return map(adminService.renameCredential(actor, actor, id, body.label()));
  }

  /** Deletes the credential identified by its base64url-encoded id. */
  @Delete("/credentials/{credentialId}")
  public HttpResponse<?> deleteCredential(
      HttpRequest<?> request, @PathVariable String credentialId) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    CredentialId id = CredentialId.fromB64Url(credentialId);
    return map(adminService.deleteCredential(actor, actor, id));
  }

  @Post("/backup-codes/regenerate")
  public HttpResponse<?> regenerateBackupCodes(HttpRequest<?> request) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return map(adminService.regenerateBackupCodes(actor, actor));
  }

  @Get("/backup-codes/count")
  public HttpResponse<?> remainingBackupCodes(HttpRequest<?> request) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return toMicronaut(
        AdminResponseMapper.toResponse(
            adminService.remainingBackupCodes(actor, actor), BackupCodesCountResponse::new));
  }

  @Post("/email/start-verification")
  public HttpResponse<?> startEmailVerification(
      HttpRequest<?> request, @Body StartEmailVerification body) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return map(adminService.startEmailVerification(actor, actor, body.email()));
  }

  /** Unauthenticated. */
  @Post("/email/complete-verification")
  public HttpResponse<?> completeEmailVerification(@Body FinishEmailVerification body) {
    return toMicronaut(
        AdminResponseMapper.toResponse(
            adminService.completeEmailVerification(body.token()), EmailVerificationResult::new));
  }

  @Post("/phone/start-verification")
  public HttpResponse<?> startPhoneVerification(
      HttpRequest<?> request, @Body StartPhoneVerification body) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return map(adminService.startPhoneVerification(actor, actor, body.phone()));
  }

  @Post("/phone/complete-verification")
  public HttpResponse<?> completePhoneVerification(
      HttpRequest<?> request, @Body FinishPhoneVerification body) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    return map(adminService.completePhoneVerification(actor, actor, body.phone(), body.code()));
  }

  /**
   * Maps an {@link AdminResult} to a Micronaut {@link HttpResponse} via the shared {@link
   * AdminResponseMapper}. Kept on the controller for backwards-compat with existing tests.
   */
  static HttpResponse<?> map(AdminResult<?> result) {
    return toMicronaut(AdminResponseMapper.toResponse(result));
  }

  private static HttpResponse<?> toMicronaut(AdminResponse response) {
    MutableHttpResponse<Object> http = HttpResponse.status(HttpStatus.valueOf(response.status()));
    response.headers().forEach(http::header);
    if (response.body() != null) {
      http.body(response.body());
    }
    return http;
  }

  /** Compile-time assertion that the AdminResult payload types are visible — no logic. */
  @SuppressWarnings("unused")
  private static List<Class<?>> payloadTypes() {
    return List.of(
        AccountSummary.class,
        CredentialSummary.class,
        BackupCodesGenerated.class,
        OtpDispatchResult.class,
        PhoneVerificationResult.class,
        BackupCodesCountResponse.class,
        EmailVerificationResult.class);
  }
}
