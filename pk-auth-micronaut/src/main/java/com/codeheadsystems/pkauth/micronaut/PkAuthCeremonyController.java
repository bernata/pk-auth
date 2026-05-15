// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import java.util.List;

/** Mounts the four WebAuthn ceremony endpoints under {@code /auth/passkeys/**}. */
@Controller("/auth/passkeys")
@Produces(MediaType.APPLICATION_JSON)
public class PkAuthCeremonyController {

  private final PasskeyAuthenticationService service;
  private final PkAuthJwtIssuer jwtIssuer;

  public PkAuthCeremonyController(PasskeyAuthenticationService service, PkAuthJwtIssuer jwtIssuer) {
    this.service = service;
    this.jwtIssuer = jwtIssuer;
  }

  @Post("/registration/start")
  public HttpResponse<StartRegistrationResponse> startRegistration(
      @Body StartRegistrationRequest req) {
    return HttpResponse.ok(service.startRegistration(req));
  }

  @Post("/registration/finish")
  public HttpResponse<RegistrationResult> finishRegistration(@Body FinishRegistrationRequest req) {
    RegistrationResult result = service.finishRegistration(req);
    return result instanceof RegistrationResult.Success
        ? HttpResponse.ok(result)
        : HttpResponse.status(HttpStatus.BAD_REQUEST).body(result);
  }

  @Post("/authentication/start")
  public HttpResponse<StartAuthenticationResponse> startAuthentication(
      @Body StartAuthenticationRequest req) {
    return HttpResponse.ok(service.startAuthentication(req));
  }

  @Post("/authentication/finish")
  public HttpResponse<AssertionResponseBody> finishAuthentication(
      @Body FinishAuthenticationRequest req) {
    AssertionResult result = service.finishAuthentication(req);
    if (result instanceof AssertionResult.Success success) {
      String token =
          jwtIssuer.issue(
              JwtClaims.forPasskey(success.userHandle(), success.credentialId(), List.of("pk")));
      return HttpResponse.ok(new AssertionResponseBody(result, token))
          .header("Authorization", "Bearer " + token);
    }
    return HttpResponse.status(HttpStatus.UNAUTHORIZED)
        .body(new AssertionResponseBody(result, null));
  }

  /** Combined response carrying the assertion result and (on success) the freshly issued JWT. */
  public record AssertionResponseBody(AssertionResult result, String token) {}
}
