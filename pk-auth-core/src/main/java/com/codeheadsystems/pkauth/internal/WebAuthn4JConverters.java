// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import com.codeheadsystems.pkauth.api.AttestationConveyance;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.ResidentKeyRequirement;
import com.codeheadsystems.pkauth.api.Transport;
import com.codeheadsystems.pkauth.api.UserVerificationRequirement;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.server.ServerProperty;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * One-way converters between pk-auth's DTOs and WebAuthn4J's input/output types. Kept in {@code
 * internal/} because every type here is implementation detail.
 */
public final class WebAuthn4JConverters {

  /** Default credential-parameter set: ES256, EdDSA, RS256, ES384, RS384 (preference order). */
  public static final List<PublicKeyCredentialParameters> DEFAULT_PUB_KEY_PARAMS =
      List.of(
          new PublicKeyCredentialParameters(
              PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
          new PublicKeyCredentialParameters(
              PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.EdDSA),
          new PublicKeyCredentialParameters(
              PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256),
          new PublicKeyCredentialParameters(
              PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES384),
          new PublicKeyCredentialParameters(
              PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS384));

  private WebAuthn4JConverters() {}

  /** Builds a WebAuthn4J {@link ServerProperty} from our RP config and a challenge. */
  public static ServerProperty serverProperty(RelyingPartyConfig rp, byte[] challenge) {
    Set<Origin> origins = new LinkedHashSet<>();
    for (String o : rp.origins()) {
      origins.add(new Origin(o));
    }
    Challenge w4jChallenge = new DefaultChallenge(challenge);
    return ServerProperty.builder().origins(origins).rpId(rp.id()).challenge(w4jChallenge).build();
  }

  /** Wraps a {@link RegistrationResponseJson} as a WebAuthn4J {@link RegistrationRequest}. */
  public static RegistrationRequest toRegistrationRequest(RegistrationResponseJson response) {
    Set<String> transports = Set.of();
    if (response.response().transports() != null) {
      transports = Set.copyOf(response.response().transports());
    }
    return new RegistrationRequest(
        response.response().attestationObject(), response.response().clientDataJSON(), transports);
  }

  /** Wraps an {@link AuthenticationResponseJson} as a WebAuthn4J {@link AuthenticationRequest}. */
  public static AuthenticationRequest toAuthenticationRequest(AuthenticationResponseJson response) {
    byte[] userHandle = response.response().userHandle();
    return new AuthenticationRequest(
        response.rawId(),
        userHandle,
        response.response().authenticatorData(),
        response.response().clientDataJSON(),
        response.response().signature());
  }

  /**
   * Reconstructs a WebAuthn4J {@link CredentialRecordImpl} from our stored {@link
   * CredentialRecord}. Used as the {@code authenticator} argument to {@code
   * AuthenticationParameters}.
   */
  public static CredentialRecordImpl toW4jCredentialRecord(
      CredentialRecord record, ObjectConverter objectConverter) {
    UUID aaguidValue = record.aaguid() == null ? AAGUID.ZERO.getValue() : record.aaguid();
    AAGUID aaguid = new AAGUID(aaguidValue);
    COSEKey coseKey =
        objectConverter.getCborMapper().readValue(record.publicKeyCose(), COSEKey.class);
    AttestedCredentialData acd =
        new AttestedCredentialData(aaguid, record.credentialId().value(), coseKey);
    Set<AuthenticatorTransport> transports = new LinkedHashSet<>();
    for (Transport t : record.transports()) {
      transports.add(AuthenticatorTransport.create(t.wireName()));
    }
    return new CredentialRecordImpl(
        new NoneAttestationStatement(),
        /* uvInitialized */ null,
        record.backupEligible(),
        record.backupState(),
        record.signCount(),
        acd,
        new AuthenticationExtensionsAuthenticatorOutputs<>(),
        /* collectedClientData */ null,
        new AuthenticationExtensionsClientOutputs<>(),
        transports);
  }

  /** Serializes a WebAuthn4J {@link COSEKey} to CBOR bytes for our credential storage. */
  public static byte[] serializeCoseKey(COSEKey coseKey, ObjectConverter objectConverter) {
    return objectConverter.getCborMapper().writeValueAsBytes(coseKey);
  }

  /** WebAuthn4J's UV-required boolean from our {@link UserVerificationRequirement}. */
  public static boolean userVerificationRequired(UserVerificationRequirement uv) {
    return uv == UserVerificationRequirement.REQUIRED;
  }

  /** Maps our enum to WebAuthn4J's {@link com.webauthn4j.data.UserVerificationRequirement}. */
  public static com.webauthn4j.data.UserVerificationRequirement toW4jUserVerification(
      UserVerificationRequirement uv) {
    return switch (uv) {
      case REQUIRED -> com.webauthn4j.data.UserVerificationRequirement.REQUIRED;
      case PREFERRED -> com.webauthn4j.data.UserVerificationRequirement.PREFERRED;
      case DISCOURAGED -> com.webauthn4j.data.UserVerificationRequirement.DISCOURAGED;
    };
  }

  /** Maps our enum to WebAuthn4J's resident-key constant set. */
  public static com.webauthn4j.data.ResidentKeyRequirement toW4jResidentKey(
      ResidentKeyRequirement rk) {
    return switch (rk) {
      case REQUIRED -> com.webauthn4j.data.ResidentKeyRequirement.REQUIRED;
      case PREFERRED -> com.webauthn4j.data.ResidentKeyRequirement.PREFERRED;
      case DISCOURAGED -> com.webauthn4j.data.ResidentKeyRequirement.DISCOURAGED;
    };
  }

  /** Maps our enum to WebAuthn4J's attestation conveyance enum. */
  public static AttestationConveyancePreference toW4jAttestationConveyance(
      AttestationConveyance ac) {
    return switch (ac) {
      case NONE -> AttestationConveyancePreference.NONE;
      case INDIRECT -> AttestationConveyancePreference.INDIRECT;
      case DIRECT -> AttestationConveyancePreference.DIRECT;
      case ENTERPRISE -> AttestationConveyancePreference.ENTERPRISE;
    };
  }
}
