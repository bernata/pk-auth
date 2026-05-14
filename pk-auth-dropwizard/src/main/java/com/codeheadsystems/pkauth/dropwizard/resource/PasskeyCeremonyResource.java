// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.resource;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.jwt.AuthMethod;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
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
 * The four WebAuthn ceremony endpoints. Mounted under {@code /auth} by {@link
 * com.codeheadsystems.pkauth.dropwizard.PkAuthBundle}.
 *
 * <p>This resource speaks pk-auth's standard JSON wire shapes (see {@link
 * com.codeheadsystems.pkauth.json.PkAuthObjectMappers}). On successful {@code
 * finish-authentication} the resource mints a pk-auth JWT and returns it alongside the assertion
 * result so single-page clients have a token to attach to subsequent admin calls.
 */
@Path("/auth")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class PasskeyCeremonyResource {

  private final PasskeyAuthenticationService service;
  private final PkAuthJwtIssuer issuer;

  @Inject
  public PasskeyCeremonyResource(PasskeyAuthenticationService service, PkAuthJwtIssuer issuer) {
    this.service = Objects.requireNonNull(service, "service");
    this.issuer = Objects.requireNonNull(issuer, "issuer");
  }

  /** Wire envelope for a successful authentication response. */
  public record AuthenticatedResponse(AssertionResult.Success assertion, String token) {}

  @POST
  @Path("/registration/start")
  public StartRegistrationResponse startRegistration(StartRegistrationRequest request) {
    return service.startRegistration(request);
  }

  @POST
  @Path("/registration/finish")
  public Response finishRegistration(FinishRegistrationRequest request) {
    RegistrationResult result = service.finishRegistration(request);
    return switch (result) {
      case RegistrationResult.Success s -> Response.ok(s).build();
      case RegistrationResult.InvalidChallenge ic ->
          Response.status(Response.Status.BAD_REQUEST).entity(ic).build();
      case RegistrationResult.OriginMismatch om ->
          Response.status(Response.Status.BAD_REQUEST).entity(om).build();
      case RegistrationResult.AttestationRejected ar ->
          Response.status(Response.Status.UNAUTHORIZED).entity(ar).build();
      case RegistrationResult.DuplicateCredential dc ->
          Response.status(Response.Status.CONFLICT).entity(dc).build();
      case RegistrationResult.InvalidPayload ip ->
          Response.status(Response.Status.BAD_REQUEST).entity(ip).build();
    };
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
    return switch (result) {
      case AssertionResult.Success s -> {
        JwtClaims claims =
            JwtClaims.forPasskey(s.userHandle(), s.credentialId(), List.of("pkauth", "webauthn"));
        // Defensive: forPasskey requires a non-null credentialId; AssertionResult.Success
        // guarantees it. Explicit AuthMethod.PASSKEY isn't needed at the call site but is implied.
        assert claims.method() == AuthMethod.PASSKEY;
        String token = issuer.issue(claims);
        yield Response.ok(new AuthenticatedResponse(s, token)).build();
      }
      case AssertionResult.UnknownCredential uc ->
          Response.status(Response.Status.UNAUTHORIZED).entity(uc).build();
      case AssertionResult.InvalidChallenge ic ->
          Response.status(Response.Status.BAD_REQUEST).entity(ic).build();
      case AssertionResult.OriginMismatch om ->
          Response.status(Response.Status.BAD_REQUEST).entity(om).build();
      case AssertionResult.CounterRegression cr ->
          Response.status(Response.Status.UNAUTHORIZED).entity(cr).build();
      case AssertionResult.UserVerificationRequired uv ->
          Response.status(Response.Status.UNAUTHORIZED).entity(uv).build();
      case AssertionResult.InvalidSignature is ->
          Response.status(Response.Status.UNAUTHORIZED).entity(is).build();
    };
  }
}
