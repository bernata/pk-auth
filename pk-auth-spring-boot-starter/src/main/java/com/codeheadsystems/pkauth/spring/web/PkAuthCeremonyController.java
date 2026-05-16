// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.web;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.CeremonyWireMapper;
import com.codeheadsystems.pkauth.api.CeremonyWireMapper.CeremonyResponse;
import com.codeheadsystems.pkauth.api.CredentialId;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.jwt.PkAuthCeremonyJwt;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.spi.CeremonyRateLimitedException;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Mounts the four ceremony endpoints under {@code /auth/passkeys}. Each endpoint forwards the
 * request to {@link PasskeyAuthenticationService} and shapes the {@code *Result} sum into an HTTP
 * response. On a successful {@code finishAuthentication} we additionally mint a JWT via {@link
 * PkAuthJwtIssuer} and return it both in the response body and as an {@code Authorization: Bearer}
 * header so the demo's JS can read it without parsing the body.
 *
 * <p>Credential persistence is the core service's responsibility — {@link
 * PasskeyAuthenticationService#finishRegistration} already calls {@code CredentialRepository.save}
 * on success. We hold a reference to {@link CredentialRepository} only so we can look up the label
 * to echo back on a successful assertion (the response body advertises which credential was used).
 *
 * <p>JWT issuance for successful assertions is delegated to {@link PkAuthCeremonyJwt} so the {@code
 * amr} claim shape stays identical across Spring, Dropwizard, and Micronaut adapters (TODO #31).
 */
@RestController
@RequestMapping("/auth/passkeys")
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

  // -- Registration ---------------------------------------------------------------------------

  @PostMapping("/registration/start")
  public StartRegistrationResponse startRegistration(
      @RequestBody StartRegistrationRequest req, HttpServletRequest httpRequest) {
    LOG.info("auth.registration.start username={}", req.username());
    return service.startRegistration(req, clientIp(httpRequest));
  }

  @PostMapping("/registration/finish")
  public ResponseEntity<Object> finishRegistration(
      @RequestBody FinishRegistrationRequest req, HttpServletRequest httpRequest) {
    RegistrationResult result = service.finishRegistration(req, clientIp(httpRequest));
    if (result instanceof RegistrationResult.Success success) {
      LOG.info(
          "auth.registration.success user={} credentialId={}",
          success.credential().userHandle(),
          success.credential().credentialId().b64url());
    }
    CeremonyResponse wire = CeremonyWireMapper.forRegistration(result);
    return ResponseEntity.status(wire.status()).body(wire.body());
  }

  // -- Authentication --------------------------------------------------------------------------

  @PostMapping("/authentication/start")
  public StartAuthenticationResponse startAuthentication(
      @RequestBody StartAuthenticationRequest req, HttpServletRequest httpRequest) {
    LOG.info("auth.authentication.start username={}", req.username());
    return service.startAuthentication(req, clientIp(httpRequest));
  }

  @PostMapping("/authentication/finish")
  public ResponseEntity<Object> finishAuthentication(
      @RequestBody FinishAuthenticationRequest req, HttpServletRequest httpRequest) {
    AssertionResult result = service.finishAuthentication(req, clientIp(httpRequest));
    if (result instanceof AssertionResult.Success success) {
      String token = PkAuthCeremonyJwt.mintForAssertion(success, jwtIssuer);
      // The label is purely cosmetic for the response body; if the credential record was deleted
      // between assertion and now (rare race), we fall back to a null label rather than 500.
      String label =
          credentialRepository
              .findByCredentialId(CredentialId.of(success.credentialId()))
              .map(CredentialRecord::label)
              .orElse(null);
      LOG.info(
          "auth.authentication.success user={} credentialId={} signCount={}",
          success.userHandle(),
          Base64Url.encode(success.credentialId()),
          success.signCount());
      CeremonyResponse wire = CeremonyWireMapper.forAssertionSuccess(success, token, label);
      return ResponseEntity.status(wire.status()).body(wire.body());
    }
    CeremonyResponse wire = CeremonyWireMapper.forAssertionError(result);
    return ResponseEntity.status(wire.status()).body(wire.body());
  }

  /**
   * Maps a {@link CeremonyRateLimitedException} thrown by {@code startRegistration} / {@code
   * startAuthentication} to a canonical {@code 429} response. The start endpoints' response
   * envelopes are not sealed result sums, so a thrown exception is the cleanest way to surface
   * limiter refusal from those entrypoints (the finish endpoints surface it via the new {@code
   * RateLimited} variants in {@link RegistrationResult} and {@link AssertionResult}).
   *
   * @since 0.9.1
   */
  @ExceptionHandler(CeremonyRateLimitedException.class)
  public ResponseEntity<Object> handleRateLimited(CeremonyRateLimitedException ex) {
    LOG.info("auth.ceremony rate-limited bucket={}", ex.bucket());
    CeremonyResponse wire = CeremonyWireMapper.rateLimited();
    return ResponseEntity.status(wire.status()).body(wire.body());
  }

  /** Extracts the source IP from the servlet request, falling back to the remote address. */
  private static String clientIp(HttpServletRequest request) {
    return request == null ? null : request.getRemoteAddr();
  }
}
