// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal.challenge;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.internal.ChallengeGenerator;
import com.codeheadsystems.pkauth.internal.ClientDataJsonParser;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.OriginValidator;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Runs all preflight checks on a registration- or authentication-finish request <em>before</em> the
 * heavy WebAuthn4J verification is invoked.
 *
 * <p>Extracted from {@code DefaultPasskeyAuthenticationService} so the ceremony methods read as
 * {@code validate → verify → map → emit} instead of an inlined wall of bail-out branches.
 *
 * <p>The validator is stateless beyond its collaborators. Each {@link #validate} call:
 *
 * <ol>
 *   <li>parses the client-supplied {@code clientDataJSON};
 *   <li>checks the ceremony marker (registration vs authentication);
 *   <li>checks the origin against {@link OriginValidator};
 *   <li>derives the challenge id and checks it matches the explicit field on the request;
 *   <li>consumes the {@link ChallengeRecord} via {@link ChallengeStore#takeOnce} (one-shot — even
 *       on later failure the record is gone);
 *   <li>checks the stored record's purpose, byte equality, and expiry.
 * </ol>
 *
 * <p>The caller maps the returned {@link ChallengeValidation} variant to the result hierarchy that
 * fits the ceremony (registration vs authentication).
 */
public final class ChallengeValidator {

  /** Ceremony marker the validator should accept in {@code clientData.type}. */
  public enum Ceremony {
    REGISTRATION("webauthn.create", ChallengeRecord.Purpose.REGISTRATION),
    AUTHENTICATION("webauthn.get", ChallengeRecord.Purpose.ASSERTION);

    private final String clientDataType;
    private final ChallengeRecord.Purpose purpose;

    Ceremony(String clientDataType, ChallengeRecord.Purpose purpose) {
      this.clientDataType = clientDataType;
      this.purpose = purpose;
    }

    public String clientDataType() {
      return clientDataType;
    }

    public ChallengeRecord.Purpose purpose() {
      return purpose;
    }
  }

  private final ChallengeStore challengeStore;
  private final OriginValidator originValidator;
  private final ClockProvider clockProvider;

  public ChallengeValidator(
      ChallengeStore challengeStore, OriginValidator originValidator, ClockProvider clockProvider) {
    this.challengeStore = Objects.requireNonNull(challengeStore, "challengeStore");
    this.originValidator = Objects.requireNonNull(originValidator, "originValidator");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
  }

  /**
   * Validate a finish-ceremony request.
   *
   * @param ceremony which ceremony this finish belongs to
   * @param challengeId the explicit challenge id sent on the request
   * @param clientDataJson raw client data bytes from the WebAuthn response
   */
  public ChallengeValidation validate(
      Ceremony ceremony, ChallengeId challengeId, byte[] clientDataJson) {
    Objects.requireNonNull(ceremony, "ceremony");
    Objects.requireNonNull(challengeId, "challengeId");
    Objects.requireNonNull(clientDataJson, "clientDataJson");

    ClientDataJsonParser.ClientData clientData;
    try {
      clientData = ClientDataJsonParser.parse(clientDataJson);
    } catch (RuntimeException ex) {
      return new ChallengeValidation.MalformedClientData("malformed clientDataJSON");
    }

    if (!ceremony.clientDataType().equals(clientData.type())) {
      return new ChallengeValidation.CeremonyTypeMismatch(
          ceremony.clientDataType(), String.valueOf(clientData.type()));
    }

    if (!originValidator.isAllowed(clientData.origin())) {
      return new ChallengeValidation.OriginMismatch(clientData.origin());
    }

    byte[] challengeBytes;
    ChallengeId derivedId;
    try {
      challengeBytes = clientData.challengeBytes();
      derivedId = ChallengeGenerator.idOf(challengeBytes);
    } catch (RuntimeException ex) {
      return new ChallengeValidation.InvalidEncoding("invalid challenge encoding");
    }
    if (!derivedId.equals(challengeId)) {
      return new ChallengeValidation.IdMismatch();
    }

    Optional<ChallengeRecord> stored = challengeStore.takeOnce(challengeId);
    if (stored.isEmpty()) {
      return new ChallengeValidation.MissingOrConsumed();
    }
    ChallengeRecord record = stored.get();

    if (record.purpose() != ceremony.purpose()) {
      return new ChallengeValidation.PurposeMismatch();
    }
    if (!Arrays.equals(record.challenge(), challengeBytes)) {
      return new ChallengeValidation.BytesMismatch();
    }
    if (clockProvider.now().isAfter(record.expiresAt())) {
      return new ChallengeValidation.Expired();
    }

    return new ChallengeValidation.Valid(record, clientData);
  }
}
