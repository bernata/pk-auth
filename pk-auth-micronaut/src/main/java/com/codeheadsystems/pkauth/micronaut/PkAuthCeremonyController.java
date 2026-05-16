// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.CeremonyWireMapper;
import com.codeheadsystems.pkauth.api.CeremonyWireMapper.CeremonyResponse;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import java.util.List;
import java.util.Map;

/**
 * Mounts the four WebAuthn ceremony endpoints under {@code /auth/passkeys/**} — same path scheme as
 * the Spring and Dropwizard adapters. All bodies are produced by {@link CeremonyWireMapper}, the
 * single source of truth for the wire contract, so the {@code @pk-auth/passkeys-browser} SDK sees
 * byte-identical JSON regardless of which adapter is in front of it.
 */
@Controller("/auth/passkeys")
@Produces(MediaType.APPLICATION_JSON)
public class PkAuthCeremonyController {

  private final PasskeyAuthenticationService service;
  private final PkAuthJwtIssuer jwtIssuer;
  private final CredentialRepository credentialRepository;

  public PkAuthCeremonyController(
      PasskeyAuthenticationService service,
      PkAuthJwtIssuer jwtIssuer,
      CredentialRepository credentialRepository) {
    this.service = service;
    this.jwtIssuer = jwtIssuer;
    this.credentialRepository = credentialRepository;
  }

  @Post("/registration/start")
  public HttpResponse<StartRegistrationResponse> startRegistration(
      @Body StartRegistrationRequest req) {
    return HttpResponse.ok(service.startRegistration(req));
  }

  @Post("/registration/finish")
  public HttpResponse<Map<String, Object>> finishRegistration(@Body FinishRegistrationRequest req) {
    CeremonyResponse wire = CeremonyWireMapper.forRegistration(service.finishRegistration(req));
    return HttpResponse.<Map<String, Object>>status(
            io.micronaut.http.HttpStatus.valueOf(wire.status()))
        .body(wire.body());
  }

  @Post("/authentication/start")
  public HttpResponse<StartAuthenticationResponse> startAuthentication(
      @Body StartAuthenticationRequest req) {
    return HttpResponse.ok(service.startAuthentication(req));
  }

  @Post("/authentication/finish")
  public HttpResponse<Map<String, Object>> finishAuthentication(
      @Body FinishAuthenticationRequest req) {
    AssertionResult result = service.finishAuthentication(req);
    if (result instanceof AssertionResult.Success success) {
      String token =
          jwtIssuer.issue(
              JwtClaims.forPasskey(success.userHandle(), success.credentialId(), List.of("pk")));
      String label =
          credentialRepository
              .findByCredentialId(success.credentialId())
              .map(CredentialRecord::label)
              .orElse(null);
      CeremonyResponse wire = CeremonyWireMapper.forAssertionSuccess(success, token, label);
      return HttpResponse.<Map<String, Object>>status(
              io.micronaut.http.HttpStatus.valueOf(wire.status()))
          .body(wire.body());
    }
    CeremonyResponse wire = CeremonyWireMapper.forAssertionError(result);
    return HttpResponse.<Map<String, Object>>status(
            io.micronaut.http.HttpStatus.valueOf(wire.status()))
        .body(wire.body());
  }
}
