// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.web;

import com.codeheadsystems.pkauth.api.AssertionResult;
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
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
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
  public StartRegistrationResponse startRegistration(@RequestBody StartRegistrationRequest req) {
    LOG.info("auth.registration.start username={}", req.username());
    return service.startRegistration(req);
  }

  @PostMapping("/registration/finish")
  public ResponseEntity<Object> finishRegistration(@RequestBody FinishRegistrationRequest req) {
    RegistrationResult result = service.finishRegistration(req);
    return switch (result) {
      case RegistrationResult.Success success -> {
        LOG.info(
            "auth.registration.success user={} credentialId={}",
            success.credential().userHandle(),
            Base64Url.encode(success.credential().credentialId()));
        yield ResponseEntity.ok(
            Map.of(
                "outcome", "success",
                "userHandle", Base64Url.encode(success.credential().userHandle().value()),
                "credentialId", Base64Url.encode(success.credential().credentialId()),
                "label", success.credential().label()));
      }
      case RegistrationResult.InvalidChallenge ic ->
          ResponseEntity.badRequest()
              .body(Map.of("outcome", "invalid_challenge", "detail", ic.detail()));
      case RegistrationResult.OriginMismatch om ->
          ResponseEntity.badRequest()
              .body(
                  Map.of(
                      "outcome", "origin_mismatch",
                      "expected", om.expected(),
                      "actual", om.actual()));
      case RegistrationResult.AttestationRejected ar ->
          ResponseEntity.badRequest()
              .body(Map.of("outcome", "attestation_rejected", "reason", ar.reason()));
      case RegistrationResult.DuplicateCredential dc ->
          ResponseEntity.status(409)
              .body(
                  Map.of(
                      "outcome",
                      "duplicate_credential",
                      "credentialId",
                      Base64Url.encode(dc.credentialId())));
      case RegistrationResult.InvalidPayload ip ->
          ResponseEntity.badRequest()
              .body(Map.of("outcome", "invalid_payload", "detail", ip.detail()));
    };
  }

  // -- Authentication --------------------------------------------------------------------------

  @PostMapping("/authentication/start")
  public StartAuthenticationResponse startAuthentication(
      @RequestBody StartAuthenticationRequest req) {
    LOG.info("auth.authentication.start username={}", req.username());
    return service.startAuthentication(req);
  }

  @PostMapping("/authentication/finish")
  public ResponseEntity<Object> finishAuthentication(@RequestBody FinishAuthenticationRequest req) {
    AssertionResult result = service.finishAuthentication(req);
    return switch (result) {
      case AssertionResult.Success success -> {
        CredentialRecord cred =
            credentialRepository
                .findByCredentialId(success.credentialId())
                .orElseThrow(() -> new IllegalStateException("credential vanished after assert"));
        String token =
            jwtIssuer.issue(
                JwtClaims.forPasskey(success.userHandle(), success.credentialId(), List.of("pwk")));
        LOG.info(
            "auth.authentication.success user={} credentialId={} signCount={}",
            success.userHandle(),
            Base64Url.encode(success.credentialId()),
            success.signCount());
        yield ResponseEntity.ok()
            .header("Authorization", "Bearer " + token)
            .body(
                Map.of(
                    "outcome",
                    "success",
                    "userHandle",
                    Base64Url.encode(success.userHandle().value()),
                    "credentialId",
                    Base64Url.encode(success.credentialId()),
                    "label",
                    cred.label(),
                    "token",
                    token));
      }
      case AssertionResult.UnknownCredential uc ->
          ResponseEntity.status(404)
              .body(
                  Map.of(
                      "outcome",
                      "unknown_credential",
                      "credentialId",
                      Base64Url.encode(uc.credentialId())));
      case AssertionResult.InvalidChallenge ic ->
          ResponseEntity.badRequest()
              .body(Map.of("outcome", "invalid_challenge", "detail", ic.detail()));
      case AssertionResult.OriginMismatch om ->
          ResponseEntity.badRequest()
              .body(
                  Map.of(
                      "outcome", "origin_mismatch",
                      "expected", om.expected(),
                      "actual", om.actual()));
      case AssertionResult.CounterRegression cr ->
          ResponseEntity.status(409)
              .body(
                  Map.of(
                      "outcome", "counter_regression",
                      "stored", cr.stored(),
                      "received", cr.received()));
      case AssertionResult.UserVerificationRequired uv ->
          ResponseEntity.status(401).body(Map.of("outcome", "user_verification_required"));
      case AssertionResult.InvalidSignature is ->
          ResponseEntity.status(401).body(Map.of("outcome", "invalid_signature"));
    };
  }
}
