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
import com.codeheadsystems.pkauth.jwt.PkAuthCeremonyJwt;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import java.util.Map;

/**
 * Mounts the four WebAuthn ceremony endpoints under {@code /auth/passkeys/**} — same path scheme as
 * the Spring and Dropwizard adapters. All bodies are produced by {@link CeremonyWireMapper}, the
 * single source of truth for the wire contract, so the {@code @pk-auth/passkeys-browser} SDK sees
 * byte-identical JSON regardless of which adapter is in front of it.
 *
 * <p><b>Threading.</b> pk-auth's SPI is blocking (JDBC, DynamoDB SDK, etc. — see TODO #29); this
 * adapter dispatches every endpoint to {@link TaskExecutors#BLOCKING} so Micronaut's Netty event
 * loop is never parked on a synchronous repository call. Hosts running on Netty event loops should
 * keep this default; hosts on a servlet container can override at the method level.
 */
@Controller("/auth/passkeys")
@Produces(MediaType.APPLICATION_JSON)
@ExecuteOn(TaskExecutors.BLOCKING)
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
      String token = PkAuthCeremonyJwt.mintForAssertion(success, jwtIssuer);
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
