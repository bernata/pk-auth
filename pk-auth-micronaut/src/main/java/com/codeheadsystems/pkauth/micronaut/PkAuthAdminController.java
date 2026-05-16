// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.admin.AccountSummary;
import com.codeheadsystems.pkauth.admin.AdminRequests.FinishEmailVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.FinishPhoneVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.RenameCredential;
import com.codeheadsystems.pkauth.admin.AdminRequests.StartEmailVerification;
import com.codeheadsystems.pkauth.admin.AdminRequests.StartPhoneVerification;
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
import com.codeheadsystems.pkauth.json.Base64Url;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Admin controller mounting the brief §6.9 endpoints under {@code /auth/admin/**}. All
 * authenticated endpoints require the {@link PkAuthJwtAuthenticationFilter} to have attached a user
 * handle to the request; {@code complete-email-verification} is intentionally unauthenticated.
 *
 * <p>Request bodies are the shared records on {@link
 * com.codeheadsystems.pkauth.admin.AdminRequests} and responses use the shared {@link
 * BackupCodesCountResponse} and {@link EmailVerificationResult} records so every adapter emits
 * byte-for-byte identical JSON.
 *
 * <p><b>Threading.</b> pk-auth's SPI is blocking (TODO #29); this adapter dispatches every endpoint
 * to {@link TaskExecutors#BLOCKING} so Micronaut's Netty event loop is never parked on a
 * synchronous repository call. Hosts running on Netty event loops should keep this default.
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

  /**
   * Renames the credential identified by its base64url-encoded id.
   *
   * @since 0.9.1
   */
  @Patch("/credentials/{credentialId}")
  public HttpResponse<?> renameCredential(
      HttpRequest<?> request, @PathVariable String credentialId, @Body RenameCredential body) {
    UserHandle actor = PkAuthJwtAuthenticationFilter.attachedUserHandle(request);
    if (actor == null) return HttpResponse.status(HttpStatus.UNAUTHORIZED);
    CredentialId id = CredentialId.fromB64Url(credentialId);
    return map(adminService.renameCredential(actor, actor, id, body.label()));
  }

  /**
   * Deletes the credential identified by its base64url-encoded id.
   *
   * @since 0.9.1
   */
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
    AdminResult<Integer> result = adminService.remainingBackupCodes(actor, actor);
    return switch (result) {
      case AdminResult.Success<Integer> s ->
          HttpResponse.ok(new BackupCodesCountResponse(s.value()));
      default -> map(result);
    };
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
    AdminResult<UserHandle> result = adminService.completeEmailVerification(body.token());
    return switch (result) {
      case AdminResult.Success<UserHandle> s ->
          HttpResponse.ok(new EmailVerificationResult(Base64Url.encode(s.value().value())));
      default -> map(result);
    };
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
   * Maps an {@link AdminResult} to an HTTP response. Non-success bodies use the unified envelope
   * {@code {"outcome": "<code>", "error": "<code>", "detail": "<message>"?}} so the wire shape is
   * consistent with ceremony errors and identical across Spring, Dropwizard, and Micronaut.
   */
  static HttpResponse<?> map(AdminResult<?> result) {
    return switch (result) {
      // Success with no payload (delete, complete-verification etc.) must not return a bare
      // `Object` body — Micronaut's Jackson codec has no encoder for it and the response would
      // become a 500. 204 No Content matches the semantic and serializes trivially.
      case AdminResult.Success<?> s when s.value() == null -> HttpResponse.noContent();
      case AdminResult.Success<?> s -> HttpResponse.ok(s.value());
      case AdminResult.NotFound<?> n ->
          HttpResponse.notFound().body(errorEnvelope("not_found", null));
      case AdminResult.Forbidden<?> f ->
          HttpResponse.status(HttpStatus.FORBIDDEN).body(errorEnvelope("forbidden", null));
      case AdminResult.ValidationFailed<?> v ->
          HttpResponse.badRequest(errorEnvelope("validation_failed", v.detail()));
      case AdminResult.Conflict<?> c ->
          HttpResponse.status(HttpStatus.CONFLICT).body(errorEnvelope("conflict", c.detail()));
      case AdminResult.RateLimited<?> r ->
          HttpResponse.status(HttpStatus.TOO_MANY_REQUESTS)
              .header("Retry-After", Long.toString(r.retryAfter().toSeconds()))
              .body(errorEnvelope("rate_limited", null));
    };
  }

  /**
   * Builds the unified error envelope: {@code {"outcome": "<code>", "error": "<code>", "detail":
   * "<message>"?}}. Both {@code outcome} and {@code error} carry the same machine-readable tag so
   * clients that key off either field keep working; {@code detail} is omitted when {@code null}.
   */
  static Map<String, Object> errorEnvelope(String code, @Nullable String detail) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("outcome", code);
    body.put("error", code);
    if (detail != null) {
      body.put("detail", detail);
    }
    return body;
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
