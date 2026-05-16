// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.resource;

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
import com.codeheadsystems.pkauth.spi.CeremonyRateLimitedException;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The four WebAuthn ceremony endpoints. Mounted under {@code /auth/passkeys} by {@link
 * com.codeheadsystems.pkauth.dropwizard.PkAuthBundle} — same path scheme as the Spring and
 * Micronaut adapters so the {@code @pk-auth/passkeys-browser} TypeScript SDK can target one base
 * path.
 *
 * <p>All bodies are produced by {@link CeremonyWireMapper}, the single source of truth for the wire
 * contract. On successful {@code finish-authentication} the resource mints a pk-auth JWT and the
 * mapper embeds it in the response body.
 */
@Path("/auth/passkeys")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class PkAuthCeremonyResource {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthCeremonyResource.class);

  private final PasskeyAuthenticationService service;
  private final PkAuthJwtIssuer issuer;
  private final CredentialRepository credentialRepository;

  @Inject
  public PkAuthCeremonyResource(
      PasskeyAuthenticationService service,
      PkAuthJwtIssuer issuer,
      CredentialRepository credentialRepository) {
    this.service = Objects.requireNonNull(service, "service");
    this.issuer = Objects.requireNonNull(issuer, "issuer");
    this.credentialRepository =
        Objects.requireNonNull(credentialRepository, "credentialRepository");
  }

  @POST
  @Path("/registration/start")
  public Response startRegistration(
      StartRegistrationRequest request, @Context HttpServletRequest httpRequest) {
    try {
      StartRegistrationResponse body = service.startRegistration(request, clientIp(httpRequest));
      return Response.ok(body).build();
    } catch (CeremonyRateLimitedException ex) {
      return rateLimitedResponse(ex);
    }
  }

  @POST
  @Path("/registration/finish")
  public Response finishRegistration(
      FinishRegistrationRequest request, @Context HttpServletRequest httpRequest) {
    CeremonyResponse wire =
        CeremonyWireMapper.forRegistration(
            service.finishRegistration(request, clientIp(httpRequest)));
    return Response.status(wire.status()).entity(wire.body()).build();
  }

  @POST
  @Path("/authentication/start")
  public Response startAuthentication(
      StartAuthenticationRequest request, @Context HttpServletRequest httpRequest) {
    try {
      StartAuthenticationResponse body =
          service.startAuthentication(request, clientIp(httpRequest));
      return Response.ok(body).build();
    } catch (CeremonyRateLimitedException ex) {
      return rateLimitedResponse(ex);
    }
  }

  @POST
  @Path("/authentication/finish")
  public Response finishAuthentication(
      FinishAuthenticationRequest request, @Context HttpServletRequest httpRequest) {
    AssertionResult result = service.finishAuthentication(request, clientIp(httpRequest));
    if (result instanceof AssertionResult.Success s) {
      String token = PkAuthCeremonyJwt.mintForAssertion(s, issuer);
      String label =
          credentialRepository
              .findByCredentialId(s.credentialId())
              .map(CredentialRecord::label)
              .orElse(null);
      CeremonyResponse wire = CeremonyWireMapper.forAssertionSuccess(s, token, label);
      return Response.status(wire.status()).entity(wire.body()).build();
    }
    CeremonyResponse wire = CeremonyWireMapper.forAssertionError(result);
    return Response.status(wire.status()).entity(wire.body()).build();
  }

  /** Extracts the source IP from the servlet request, falling back to the remote address. */
  private static String clientIp(HttpServletRequest httpRequest) {
    return httpRequest == null ? null : httpRequest.getRemoteAddr();
  }

  /**
   * Maps a {@link CeremonyRateLimitedException} thrown by {@code startRegistration} / {@code
   * startAuthentication} to the canonical {@code 429} wire shape. See {@link
   * CeremonyWireMapper#rateLimited()}.
   *
   * @since 0.9.1
   */
  private static Response rateLimitedResponse(CeremonyRateLimitedException ex) {
    LOG.info("auth.ceremony rate-limited bucket={}", ex.bucket());
    CeremonyResponse wire = CeremonyWireMapper.rateLimited();
    return Response.status(wire.status()).entity(wire.body()).build();
  }
}
