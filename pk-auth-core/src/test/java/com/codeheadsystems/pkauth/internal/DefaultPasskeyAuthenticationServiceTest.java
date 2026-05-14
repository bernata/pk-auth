// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson.AuthenticatorAssertionResponseJson;
import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson.AuthenticatorAttestationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.config.CeremonyConfig;
import com.codeheadsystems.pkauth.config.CounterRegressionPolicy;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.metrics.Metrics;
import com.codeheadsystems.pkauth.spi.AttestationTrustPolicy;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OriginValidator;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.verifier.exception.BadChallengeException;
import com.webauthn4j.verifier.exception.BadOriginException;
import com.webauthn4j.verifier.exception.BadSignatureException;
import com.webauthn4j.verifier.exception.MaliciousCounterValueException;
import com.webauthn4j.verifier.exception.UserNotVerifiedException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class DefaultPasskeyAuthenticationServiceTest {

  private static final Instant NOW = Instant.parse("2026-05-13T12:00:00Z");
  private static final byte[] CHALLENGE = filled(32, (byte) 1);
  private static final ChallengeId CHALLENGE_ID = new ChallengeId(Base64Url.encode(CHALLENGE));
  private static final UserHandle USER_HANDLE = UserHandle.of(filled(16, (byte) 9));
  private static final byte[] CRED_ID = filled(20, (byte) 2);

  private final JsonMapper jsonMapper =
      JsonMapper.builder()
          .changeDefaultPropertyInclusion(v -> v.withValueInclusion(JsonInclude.Include.NON_NULL))
          .build();

  private WebAuthnManager webAuthnManager;
  private CredentialRepository credentialRepository;
  private UserLookup userLookup;
  private ChallengeStore challengeStore;
  private OriginValidator originValidator;
  private AttestationTrustPolicy attestationTrustPolicy;
  private Metrics metrics;

  private DefaultPasskeyAuthenticationService service;

  @BeforeEach
  void setUp() {
    webAuthnManager = mock(WebAuthnManager.class);
    credentialRepository = mock(CredentialRepository.class);
    userLookup = mock(UserLookup.class);
    challengeStore = mock(ChallengeStore.class);
    originValidator = mock(OriginValidator.class);
    attestationTrustPolicy = mock(AttestationTrustPolicy.class);
    metrics = mock(Metrics.class);

    lenient().when(originValidator.isAllowed("https://example.com")).thenReturn(true);
    lenient()
        .when(attestationTrustPolicy.evaluate(any()))
        .thenReturn(new AttestationTrustPolicy.Decision.Trusted());

    service = newService(CounterRegressionPolicy.REJECT);
  }

  private DefaultPasskeyAuthenticationService newService(CounterRegressionPolicy policy) {
    RelyingPartyConfig rp =
        new RelyingPartyConfig("example.com", "Example", Set.of("https://example.com"));
    CeremonyConfig ceremonyConfig =
        new CeremonyConfig(
            Duration.ofMinutes(5),
            UserVerificationRequirement.PREFERRED,
            ResidentKeyRequirement.PREFERRED,
            AttestationConveyance.NONE,
            policy);

    SecureRandom random =
        new SecureRandom() {
          @Override
          public void nextBytes(byte[] bytes) {
            System.arraycopy(CHALLENGE, 0, bytes, 0, Math.min(bytes.length, CHALLENGE.length));
          }
        };

    return new DefaultPasskeyAuthenticationService(
        webAuthnManager,
        new ObjectConverter(),
        credentialRepository,
        userLookup,
        challengeStore,
        ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC)),
        originValidator,
        attestationTrustPolicy,
        rp,
        ceremonyConfig,
        new ChallengeGenerator(random),
        metrics);
  }

  // -- Start --------------------------------------------------------------------------------

  @Test
  void startRegistrationPersistsChallengeAndReturnsEnvelope() {
    when(userLookup.createOrGetUserHandle("alice")).thenReturn(USER_HANDLE);
    when(credentialRepository.findByUserHandle(USER_HANDLE)).thenReturn(List.of());

    StartRegistrationResponse resp =
        service.startRegistration(new StartRegistrationRequest("alice", "Alice", null, null));

    assertThat(resp.challengeId()).isEqualTo(CHALLENGE_ID);
    assertThat(resp.publicKey().rp().id()).isEqualTo("example.com");
    assertThat(resp.publicKey().user().name()).isEqualTo("alice");
    assertThat(resp.publicKey().user().displayName()).isEqualTo("Alice");
    assertThat(resp.publicKey().challenge()).containsExactly(CHALLENGE);
    assertThat(resp.publicKey().excludeCredentials()).isNull();

    verify(challengeStore)
        .put(eq(CHALLENGE_ID), any(ChallengeRecord.class), eq(Duration.ofMinutes(5)));
    verify(metrics).incrementCounter("pkauth.registration.start", "rp", "example.com");
  }

  @Test
  void startAuthenticationIncludesAllowCredentialsForKnownUser() {
    when(userLookup.findUserHandleByUsername("alice")).thenReturn(Optional.of(USER_HANDLE));
    when(credentialRepository.findByUserHandle(USER_HANDLE))
        .thenReturn(List.of(stubStoredCredential()));

    StartAuthenticationResponse resp =
        service.startAuthentication(new StartAuthenticationRequest("alice", null));

    assertThat(resp.publicKey().rpId()).isEqualTo("example.com");
    assertThat(resp.publicKey().allowCredentials()).hasSize(1);
    assertThat(resp.publicKey().userVerification())
        .isEqualTo(UserVerificationRequirement.PREFERRED);
    verify(metrics).incrementCounter("pkauth.authentication.start", "rp", "example.com");
  }

  @Test
  void startAuthenticationOmitsAllowCredentialsForUsernamelessFlow() {
    StartAuthenticationResponse resp =
        service.startAuthentication(new StartAuthenticationRequest(null, null));
    assertThat(resp.publicKey().allowCredentials()).isNull();
  }

  // -- Finish registration ------------------------------------------------------------------

  @Test
  void finishRegistrationRejectsMalformedClientDataJson() {
    RegistrationResult result = service.finishRegistration(finishReg(new byte[] {1, 2, 3}));
    assertThat(result).isInstanceOf(RegistrationResult.InvalidPayload.class);
  }

  @Test
  void finishRegistrationRejectsWrongClientDataType() {
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    RegistrationResult result = service.finishRegistration(finishReg(cd));
    assertThat(result).isInstanceOf(RegistrationResult.InvalidPayload.class);
  }

  @Test
  void finishRegistrationRejectsBadOrigin() {
    byte[] cd =
        clientData("webauthn.create", Base64Url.encode(CHALLENGE), "https://evil.example.com");
    RegistrationResult result = service.finishRegistration(finishReg(cd));
    assertThat(result)
        .isInstanceOfSatisfying(
            RegistrationResult.OriginMismatch.class,
            om -> assertThat(om.actual()).isEqualTo("https://evil.example.com"));
  }

  @Test
  void finishRegistrationRejectsChallengeIdMismatch() {
    byte[] otherChallenge = filled(32, (byte) 7);
    byte[] cd =
        clientData("webauthn.create", Base64Url.encode(otherChallenge), "https://example.com");
    RegistrationResult result = service.finishRegistration(finishReg(cd));
    assertThat(result).isInstanceOf(RegistrationResult.InvalidChallenge.class);
  }

  @Test
  void finishRegistrationRejectsMissingChallenge() {
    byte[] cd = clientData("webauthn.create", Base64Url.encode(CHALLENGE), "https://example.com");
    when(challengeStore.takeOnce(CHALLENGE_ID)).thenReturn(Optional.empty());
    RegistrationResult result = service.finishRegistration(finishReg(cd));
    assertThat(result).isInstanceOf(RegistrationResult.InvalidChallenge.class);
  }

  @Test
  void finishRegistrationRejectsCrossPurposeChallenge() {
    primeStoredChallenge(ChallengeRecord.Purpose.ASSERTION);
    byte[] cd = clientData("webauthn.create", Base64Url.encode(CHALLENGE), "https://example.com");
    RegistrationResult result = service.finishRegistration(finishReg(cd));
    assertThat(result).isInstanceOf(RegistrationResult.InvalidChallenge.class);
  }

  @Test
  void finishRegistrationRejectsExpiredChallenge() {
    when(challengeStore.takeOnce(CHALLENGE_ID))
        .thenReturn(
            Optional.of(
                new ChallengeRecord(
                    CHALLENGE,
                    ChallengeRecord.Purpose.REGISTRATION,
                    USER_HANDLE,
                    NOW.minusSeconds(1))));
    byte[] cd = clientData("webauthn.create", Base64Url.encode(CHALLENGE), "https://example.com");
    RegistrationResult result = service.finishRegistration(finishReg(cd));
    assertThat(result).isInstanceOf(RegistrationResult.InvalidChallenge.class);
  }

  @Test
  void finishRegistrationMapsBadOriginVerificationException() throws Exception {
    primeStoredChallenge(ChallengeRecord.Purpose.REGISTRATION);
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.RegistrationRequest.class), any(RegistrationParameters.class)))
        .thenThrow(new BadOriginException("nope"));
    byte[] cd = clientData("webauthn.create", Base64Url.encode(CHALLENGE), "https://example.com");
    RegistrationResult result = service.finishRegistration(finishReg(cd));
    assertThat(result).isInstanceOf(RegistrationResult.OriginMismatch.class);
  }

  @Test
  void finishRegistrationMapsBadChallengeVerificationException() throws Exception {
    primeStoredChallenge(ChallengeRecord.Purpose.REGISTRATION);
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.RegistrationRequest.class), any(RegistrationParameters.class)))
        .thenThrow(new BadChallengeException("nope"));
    byte[] cd = clientData("webauthn.create", Base64Url.encode(CHALLENGE), "https://example.com");
    RegistrationResult result = service.finishRegistration(finishReg(cd));
    assertThat(result).isInstanceOf(RegistrationResult.InvalidChallenge.class);
  }

  @Test
  void finishRegistrationMapsBadSignatureVerificationException() throws Exception {
    primeStoredChallenge(ChallengeRecord.Purpose.REGISTRATION);
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.RegistrationRequest.class), any(RegistrationParameters.class)))
        .thenThrow(new BadSignatureException("bad"));
    byte[] cd = clientData("webauthn.create", Base64Url.encode(CHALLENGE), "https://example.com");
    RegistrationResult result = service.finishRegistration(finishReg(cd));
    assertThat(result).isInstanceOf(RegistrationResult.AttestationRejected.class);
  }

  @Test
  void finishRegistrationMapsDataConversionException() throws Exception {
    primeStoredChallenge(ChallengeRecord.Purpose.REGISTRATION);
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.RegistrationRequest.class), any(RegistrationParameters.class)))
        .thenThrow(new DataConversionException("malformed"));
    byte[] cd = clientData("webauthn.create", Base64Url.encode(CHALLENGE), "https://example.com");
    RegistrationResult result = service.finishRegistration(finishReg(cd));
    assertThat(result).isInstanceOf(RegistrationResult.InvalidPayload.class);
  }

  // -- Finish authentication ----------------------------------------------------------------

  @Test
  void finishAuthenticationRejectsUnknownCredential() {
    primeStoredChallenge(ChallengeRecord.Purpose.ASSERTION);
    when(credentialRepository.findByCredentialId(CRED_ID)).thenReturn(Optional.empty());
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    AssertionResult result = service.finishAuthentication(finishAuth(cd));
    assertThat(result).isInstanceOf(AssertionResult.UnknownCredential.class);
  }

  @Test
  void finishAuthenticationRejectsBadOrigin() {
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://evil.com");
    AssertionResult result = service.finishAuthentication(finishAuth(cd));
    assertThat(result).isInstanceOf(AssertionResult.OriginMismatch.class);
  }

  @Test
  void finishAuthenticationRejectsCrossPurposeChallenge() {
    primeStoredChallenge(ChallengeRecord.Purpose.REGISTRATION);
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    AssertionResult result = service.finishAuthentication(finishAuth(cd));
    assertThat(result).isInstanceOf(AssertionResult.InvalidChallenge.class);
  }

  @Test
  void finishAuthenticationMapsUserNotVerified() throws Exception {
    primeStoredChallenge(ChallengeRecord.Purpose.ASSERTION);
    primeStoredCredentialForAssertion();
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.AuthenticationRequest.class),
            any(AuthenticationParameters.class)))
        .thenThrow(new UserNotVerifiedException("uv"));
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    AssertionResult result = service.finishAuthentication(finishAuth(cd));
    assertThat(result).isInstanceOf(AssertionResult.UserVerificationRequired.class);
  }

  @Test
  void finishAuthenticationMapsBadSignature() throws Exception {
    primeStoredChallenge(ChallengeRecord.Purpose.ASSERTION);
    primeStoredCredentialForAssertion();
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.AuthenticationRequest.class),
            any(AuthenticationParameters.class)))
        .thenThrow(new BadSignatureException("bad sig"));
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    AssertionResult result = service.finishAuthentication(finishAuth(cd));
    assertThat(result).isInstanceOf(AssertionResult.InvalidSignature.class);
  }

  @Test
  void finishAuthenticationCounterRegressionRejectMode() throws Exception {
    primeStoredChallenge(ChallengeRecord.Purpose.ASSERTION);
    primeStoredCredentialForAssertion();
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.AuthenticationRequest.class),
            any(AuthenticationParameters.class)))
        .thenThrow(new MaliciousCounterValueException("counter went down", 0L, 0L));
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    AssertionResult result = service.finishAuthentication(finishAuth(cd));
    assertThat(result).isInstanceOf(AssertionResult.CounterRegression.class);
    verify(credentialRepository, never()).updateSignCount(any(), anyLongValue(), any());
  }

  @Test
  void finishAuthenticationCounterRegressionWarnModeAccepts() throws Exception {
    service = newService(CounterRegressionPolicy.WARN);
    primeStoredChallenge(ChallengeRecord.Purpose.ASSERTION);
    primeStoredCredentialForAssertion();
    when(webAuthnManager.verify(
            any(com.webauthn4j.data.AuthenticationRequest.class),
            any(AuthenticationParameters.class)))
        .thenThrow(new MaliciousCounterValueException("counter went down", 0L, 0L));
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    AssertionResult result = service.finishAuthentication(finishAuth(cd));
    assertThat(result).isInstanceOf(AssertionResult.Success.class);
    // WARN mode does NOT bump the stored count.
    verify(credentialRepository, never()).updateSignCount(any(), anyLongValue(), any());
  }

  @Test
  void finishAuthenticationHappyPathUpdatesSignCount() throws Exception {
    primeStoredChallenge(ChallengeRecord.Purpose.ASSERTION);
    primeStoredCredentialForAssertion();

    AuthenticationData data = mock(AuthenticationData.class);
    com.webauthn4j.data.attestation.authenticator.AuthenticatorData<?> authData =
        mock(com.webauthn4j.data.attestation.authenticator.AuthenticatorData.class);
    when(authData.getSignCount()).thenReturn(42L);
    when(data.getAuthenticatorData()).thenAnswer(inv -> authData);

    when(webAuthnManager.verify(
            any(com.webauthn4j.data.AuthenticationRequest.class),
            any(AuthenticationParameters.class)))
        .thenReturn(data);

    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    AssertionResult result = service.finishAuthentication(finishAuth(cd));

    assertThat(result)
        .isInstanceOfSatisfying(
            AssertionResult.Success.class,
            s -> {
              assertThat(s.userHandle()).isEqualTo(USER_HANDLE);
              assertThat(s.signCount()).isEqualTo(42L);
            });
    verify(credentialRepository).updateSignCount(eq(CRED_ID), eq(42L), eq(NOW));
    verify(metrics).incrementCounter("pkauth.authentication.outcome", "result", "Success");
  }

  // -- Fixtures -----------------------------------------------------------------------------

  private FinishRegistrationRequest finishReg(byte[] clientDataJson) {
    return new FinishRegistrationRequest(
        CHALLENGE_ID,
        "alice",
        "Test key",
        new RegistrationResponseJson(
            CRED_ID,
            CRED_ID,
            new AuthenticatorAttestationResponseJson(
                clientDataJson, new byte[] {(byte) 0xa0}, null, null, null, null),
            null,
            null,
            "public-key"));
  }

  private FinishAuthenticationRequest finishAuth(byte[] clientDataJson) {
    return new FinishAuthenticationRequest(
        CHALLENGE_ID,
        new AuthenticationResponseJson(
            CRED_ID,
            CRED_ID,
            new AuthenticatorAssertionResponseJson(
                clientDataJson, new byte[] {(byte) 0xa0}, new byte[] {(byte) 0xb0}, null),
            null,
            null,
            "public-key"));
  }

  private byte[] clientData(String type, String challenge, String origin) {
    var node = jsonMapper.createObjectNode();
    node.put("type", type);
    node.put("challenge", challenge);
    node.put("origin", origin);
    return jsonMapper.writeValueAsString(node).getBytes(StandardCharsets.UTF_8);
  }

  private void primeStoredChallenge(ChallengeRecord.Purpose purpose) {
    when(challengeStore.takeOnce(CHALLENGE_ID))
        .thenReturn(
            Optional.of(
                new ChallengeRecord(CHALLENGE, purpose, USER_HANDLE, NOW.plusSeconds(300))));
  }

  private void primeStoredCredentialForAssertion() {
    when(credentialRepository.findByCredentialId(CRED_ID))
        .thenReturn(Optional.of(stubStoredCredential()));
  }

  private CredentialRecord stubStoredCredential() {
    return new CredentialRecord(
        CRED_ID,
        USER_HANDLE,
        stubCoseKeyBytes(),
        0L,
        "Test",
        null,
        Set.of(),
        true,
        true,
        NOW.minusSeconds(60),
        null);
  }

  private static byte[] stubCoseKeyBytes() {
    ObjectConverter oc = new ObjectConverter();
    com.webauthn4j.data.attestation.authenticator.EC2COSEKey key =
        com.webauthn4j.data.attestation.authenticator.EC2COSEKey.createFromUncompressedECCKey(
            uncompressedEcPoint());
    return WebAuthn4JConverters.serializeCoseKey(key, oc);
  }

  private static byte[] uncompressedEcPoint() {
    // 65 bytes: 0x04 || X (32) || Y (32). The values aren't validated; we just need bytes that
    // round-trip through the CBOR codec, which we never actually verify against in these mocks.
    byte[] point = new byte[65];
    point[0] = 0x04;
    for (int i = 1; i < point.length; i++) {
      point[i] = (byte) i;
    }
    return point;
  }

  private static byte[] filled(int len, byte v) {
    byte[] out = new byte[len];
    java.util.Arrays.fill(out, v);
    return out;
  }

  // Mockito convenience — eq(long) shadow without the boxing dance in callers.
  private static long anyLongValue() {
    return org.mockito.ArgumentMatchers.anyLong();
  }
}
