// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal.challenge;

import com.codeheadsystems.pkauth.internal.ClientDataJsonParser;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import java.util.Objects;

/**
 * Sealed outcome of {@link ChallengeValidator#validate}. Each variant maps 1:1 to a non-success
 * variant of {@code RegistrationResult} / {@code AssertionResult}, with {@link Valid} being the
 * only "continue" case carrying the parsed client data and the consumed challenge record so the
 * caller can hand them to WebAuthn4J.
 */
public sealed interface ChallengeValidation {

  /**
   * The challenge passed every preflight check. The caller has now consumed the challenge from the
   * store and owns {@code record}; nobody else can use it again.
   */
  record Valid(ChallengeRecord record, ClientDataJsonParser.ClientData clientData)
      implements ChallengeValidation {
    public Valid {
      Objects.requireNonNull(record, "record");
      Objects.requireNonNull(clientData, "clientData");
    }
  }

  /** The {@code clientDataJSON} bytes were not parseable JSON or violated the expected shape. */
  record MalformedClientData(String detail) implements ChallengeValidation {
    public MalformedClientData {
      Objects.requireNonNull(detail, "detail");
    }
  }

  /**
   * {@code clientData.type} did not match the expected ceremony marker ({@code webauthn.create} for
   * registration, {@code webauthn.get} for authentication).
   */
  record CeremonyTypeMismatch(String expected, String actual) implements ChallengeValidation {
    public CeremonyTypeMismatch {
      Objects.requireNonNull(expected, "expected");
      Objects.requireNonNull(actual, "actual");
    }
  }

  /** The client-reported origin did not match an allowed origin. */
  record OriginMismatch(String actual) implements ChallengeValidation {
    public OriginMismatch {
      Objects.requireNonNull(actual, "actual");
    }
  }

  /** The base64url-encoded challenge in {@code clientData} could not be decoded. */
  record InvalidEncoding(String detail) implements ChallengeValidation {
    public InvalidEncoding {
      Objects.requireNonNull(detail, "detail");
    }
  }

  /**
   * The challenge id derived from {@code clientData.challenge} did not match the explicit
   * challengeId field on the request. This catches a tampered or swapped client payload.
   */
  record IdMismatch() implements ChallengeValidation {}

  /** No record exists for the challenge id — unknown, expired, or already consumed. */
  record MissingOrConsumed() implements ChallengeValidation {}

  /**
   * The stored challenge belongs to a different ceremony (e.g. an assertion finish was given a
   * registration challenge id).
   */
  record PurposeMismatch() implements ChallengeValidation {}

  /**
   * The stored challenge bytes did not equal the bytes that the client returned in {@code
   * clientData.challenge}.
   */
  record BytesMismatch() implements ChallengeValidation {}

  /** The challenge record has expired according to the {@code ClockProvider}. */
  record Expired() implements ChallengeValidation {}

  /**
   * Visitor used by {@link #toResult(ChallengeValidation, Mapper)} to translate a non-{@code Valid}
   * variant into a caller-defined result type. Centralises the dispatch so every call site uses the
   * same enumeration and the compiler catches new variants.
   *
   * @param <R> the result type produced by the mapper
   * @since 0.9.1
   */
  interface Mapper<R> {
    R malformedClientData(String detail);

    R ceremonyTypeMismatch(String expected, String actual);

    R originMismatch(String actual);

    R invalidEncoding(String detail);

    R idMismatch();

    R missingOrConsumed();

    R purposeMismatch();

    R bytesMismatch();

    R expired();
  }

  /**
   * Dispatches {@code v} to the corresponding {@code mapper} method. Throws if {@code v} is the
   * {@code Valid} variant — callers must short-circuit success before invoking this helper.
   *
   * @since 0.9.1
   */
  static <R> R toResult(ChallengeValidation v, Mapper<R> mapper) {
    return switch (v) {
      case Valid ignored ->
          throw new IllegalStateException("ChallengeValidation.toResult called on Valid");
      case MalformedClientData m -> mapper.malformedClientData(m.detail());
      case CeremonyTypeMismatch t -> mapper.ceremonyTypeMismatch(t.expected(), t.actual());
      case OriginMismatch o -> mapper.originMismatch(o.actual());
      case InvalidEncoding e -> mapper.invalidEncoding(e.detail());
      case IdMismatch ignored -> mapper.idMismatch();
      case MissingOrConsumed ignored -> mapper.missingOrConsumed();
      case PurposeMismatch ignored -> mapper.purposeMismatch();
      case BytesMismatch ignored -> mapper.bytesMismatch();
      case Expired ignored -> mapper.expired();
    };
  }
}
