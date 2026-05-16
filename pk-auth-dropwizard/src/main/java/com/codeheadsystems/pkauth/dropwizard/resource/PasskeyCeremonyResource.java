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
import com.codeheadsystems.pkauth.jwt.AuthMethod;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Objects;

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
public class PasskeyCeremonyResource {

  private final PasskeyAuthenticationService service;
  private final PkAuthJwtIssuer issuer;
  private final CredentialRepository credentialRepository;

  @Inject
  public PasskeyCeremonyResource(
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
  public StartRegistrationResponse startRegistration(StartRegistrationRequest request) {
    return service.startRegistration(request);
  }

  @POST
  @Path("/registration/finish")
  public Response finishRegistration(FinishRegistrationRequest request) {
    CeremonyResponse wire = CeremonyWireMapper.forRegistration(service.finishRegistration(request));
    return Response.status(wire.status()).entity(wire.body()).build();
  }

  @POST
  @Path("/authentication/start")
  public StartAuthenticationResponse startAuthentication(StartAuthenticationRequest request) {
    return service.startAuthentication(request);
  }

  @POST
  @Path("/authentication/finish")
  public Response finishAuthentication(FinishAuthenticationRequest request) {
    AssertionResult result = service.finishAuthentication(request);
    if (result instanceof AssertionResult.Success s) {
      JwtClaims claims =
          JwtClaims.forPasskey(s.userHandle(), s.credentialId(), List.of("pkauth", "webauthn"));
      // Defensive: forPasskey requires a non-null credentialId; AssertionResult.Success
      // guarantees it. Explicit AuthMethod.PASSKEY isn't needed at the call site but is implied.
      assert claims.method() == AuthMethod.PASSKEY;
      String token = issuer.issue(claims);
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
}
