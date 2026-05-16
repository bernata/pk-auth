// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.CeremonyWireMapper;
import com.codeheadsystems.pkauth.api.CeremonyWireMapper.CeremonyResponse;
import com.codeheadsystems.pkauth.api.CredentialId;
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
import com.codeheadsystems.pkauth.spi.CeremonyRateLimitedException;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Error;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import java.net.InetSocketAddress;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthCeremonyController.class);

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
      @Body StartRegistrationRequest req, HttpRequest<?> httpRequest) {
    return HttpResponse.ok(service.startRegistration(req, clientIp(httpRequest)));
  }

  @Post("/registration/finish")
  public HttpResponse<Map<String, Object>> finishRegistration(
      @Body FinishRegistrationRequest req, HttpRequest<?> httpRequest) {
    CeremonyResponse wire =
        CeremonyWireMapper.forRegistration(service.finishRegistration(req, clientIp(httpRequest)));
    return HttpResponse.<Map<String, Object>>status(
            io.micronaut.http.HttpStatus.valueOf(wire.status()))
        .body(wire.body());
  }

  @Post("/authentication/start")
  public HttpResponse<StartAuthenticationResponse> startAuthentication(
      @Body StartAuthenticationRequest req, HttpRequest<?> httpRequest) {
    return HttpResponse.ok(service.startAuthentication(req, clientIp(httpRequest)));
  }

  @Post("/authentication/finish")
  public HttpResponse<Map<String, Object>> finishAuthentication(
      @Body FinishAuthenticationRequest req, HttpRequest<?> httpRequest) {
    AssertionResult result = service.finishAuthentication(req, clientIp(httpRequest));
    if (result instanceof AssertionResult.Success success) {
      String token = PkAuthCeremonyJwt.mintForAssertion(success, jwtIssuer);
      String label =
          credentialRepository
              .findByCredentialId(CredentialId.of(success.credentialId()))
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

  /**
   * Maps a {@link CeremonyRateLimitedException} thrown by {@code startRegistration} / {@code
   * startAuthentication} to the canonical {@code 429} wire shape. The finish endpoints surface
   * limiter refusal through {@code AssertionResult.RateLimited} / {@code
   * RegistrationResult.RateLimited} and so do not route through this handler.
   *
   * @since 0.9.1
   */
  @Error(exception = CeremonyRateLimitedException.class)
  public HttpResponse<Map<String, Object>> handleRateLimited(CeremonyRateLimitedException ex) {
    LOG.info("auth.ceremony rate-limited bucket={}", ex.bucket());
    CeremonyResponse wire = CeremonyWireMapper.rateLimited();
    return HttpResponse.<Map<String, Object>>status(
            io.micronaut.http.HttpStatus.valueOf(wire.status()))
        .body(wire.body());
  }

  /**
   * Extracts the source IP from the Micronaut {@link HttpRequest}. Falls back to {@code null} when
   * the request lacks a remote address (e.g. in-process test dispatch).
   */
  private static String clientIp(HttpRequest<?> request) {
    if (request == null) {
      return null;
    }
    InetSocketAddress addr = request.getRemoteAddress();
    if (addr == null || addr.getAddress() == null) {
      return null;
    }
    return addr.getAddress().getHostAddress();
  }
}
