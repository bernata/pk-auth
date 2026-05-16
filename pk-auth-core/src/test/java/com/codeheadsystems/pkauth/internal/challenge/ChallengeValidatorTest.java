// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal.challenge;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.OriginValidator;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class ChallengeValidatorTest {

  private static final Instant NOW = Instant.parse("2026-05-13T12:00:00Z");
  private static final byte[] CHALLENGE = filled(32, (byte) 1);
  private static final ChallengeId CHALLENGE_ID = new ChallengeId(Base64Url.encode(CHALLENGE));
  private static final UserHandle USER_HANDLE = UserHandle.of(filled(16, (byte) 9));

  private final JsonMapper jsonMapper =
      JsonMapper.builder()
          .changeDefaultPropertyInclusion(v -> v.withValueInclusion(JsonInclude.Include.NON_NULL))
          .build();

  private ChallengeStore challengeStore;
  private OriginValidator originValidator;
  private ChallengeValidator validator;

  @BeforeEach
  void setUp() {
    challengeStore = mock(ChallengeStore.class);
    originValidator = mock(OriginValidator.class);
    lenient().when(originValidator.isAllowed("https://example.com")).thenReturn(true);
    validator =
        new ChallengeValidator(
            challengeStore,
            originValidator,
            ClockProvider.fromClock(Clock.fixed(NOW, ZoneOffset.UTC)));
  }

  @Test
  void validReturnsValidWithRecordAndClientData() {
    primeStore(ChallengeRecord.Purpose.ASSERTION, NOW.plusSeconds(60));
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    ChallengeValidation out =
        validator.validate(ChallengeValidator.Ceremony.AUTHENTICATION, CHALLENGE_ID, cd);
    assertThat(out)
        .isInstanceOfSatisfying(
            ChallengeValidation.Valid.class,
            v -> {
              assertThat(v.record().purpose()).isEqualTo(ChallengeRecord.Purpose.ASSERTION);
              assertThat(v.clientData().origin()).isEqualTo("https://example.com");
            });
  }

  @Test
  void malformedClientDataReturnsMalformedClientData() {
    ChallengeValidation out =
        validator.validate(
            ChallengeValidator.Ceremony.REGISTRATION, CHALLENGE_ID, new byte[] {1, 2, 3});
    assertThat(out).isInstanceOf(ChallengeValidation.MalformedClientData.class);
  }

  @Test
  void wrongTypeReturnsCeremonyTypeMismatch() {
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    ChallengeValidation out =
        validator.validate(ChallengeValidator.Ceremony.REGISTRATION, CHALLENGE_ID, cd);
    assertThat(out)
        .isInstanceOfSatisfying(
            ChallengeValidation.CeremonyTypeMismatch.class,
            m -> {
              assertThat(m.expected()).isEqualTo("webauthn.create");
              assertThat(m.actual()).isEqualTo("webauthn.get");
            });
  }

  @Test
  void disallowedOriginReturnsOriginMismatch() {
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://evil.com");
    ChallengeValidation out =
        validator.validate(ChallengeValidator.Ceremony.AUTHENTICATION, CHALLENGE_ID, cd);
    assertThat(out)
        .isInstanceOfSatisfying(
            ChallengeValidation.OriginMismatch.class,
            m -> assertThat(m.actual()).isEqualTo("https://evil.com"));
  }

  @Test
  void challengeIdMismatchReturnsIdMismatch() {
    byte[] otherChallenge = filled(32, (byte) 7);
    byte[] cd = clientData("webauthn.get", Base64Url.encode(otherChallenge), "https://example.com");
    ChallengeValidation out =
        validator.validate(ChallengeValidator.Ceremony.AUTHENTICATION, CHALLENGE_ID, cd);
    assertThat(out).isInstanceOf(ChallengeValidation.IdMismatch.class);
  }

  @Test
  void missingStoredRecordReturnsMissingOrConsumed() {
    when(challengeStore.takeOnce(CHALLENGE_ID)).thenReturn(Optional.empty());
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    ChallengeValidation out =
        validator.validate(ChallengeValidator.Ceremony.AUTHENTICATION, CHALLENGE_ID, cd);
    assertThat(out).isInstanceOf(ChallengeValidation.MissingOrConsumed.class);
  }

  @Test
  void crossPurposeChallengeReturnsPurposeMismatch() {
    primeStore(ChallengeRecord.Purpose.REGISTRATION, NOW.plusSeconds(60));
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    ChallengeValidation out =
        validator.validate(ChallengeValidator.Ceremony.AUTHENTICATION, CHALLENGE_ID, cd);
    assertThat(out).isInstanceOf(ChallengeValidation.PurposeMismatch.class);
  }

  @Test
  void mismatchedStoredBytesReturnsBytesMismatch() {
    // store has different bytes than what client returned. Trick: ChallengeId is derived from
    // bytes, so to bypass IdMismatch we have to store a record under the same id but with
    // different bytes — which only happens if the store hands back tampered data. Emulate that.
    when(challengeStore.takeOnce(CHALLENGE_ID))
        .thenReturn(
            Optional.of(
                new ChallengeRecord(
                    filled(32, (byte) 8),
                    ChallengeRecord.Purpose.ASSERTION,
                    USER_HANDLE,
                    NOW.plusSeconds(60))));
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    ChallengeValidation out =
        validator.validate(ChallengeValidator.Ceremony.AUTHENTICATION, CHALLENGE_ID, cd);
    assertThat(out).isInstanceOf(ChallengeValidation.BytesMismatch.class);
  }

  @Test
  void expiredChallengeReturnsExpired() {
    primeStore(ChallengeRecord.Purpose.ASSERTION, NOW.minusSeconds(1));
    byte[] cd = clientData("webauthn.get", Base64Url.encode(CHALLENGE), "https://example.com");
    ChallengeValidation out =
        validator.validate(ChallengeValidator.Ceremony.AUTHENTICATION, CHALLENGE_ID, cd);
    assertThat(out).isInstanceOf(ChallengeValidation.Expired.class);
  }

  private void primeStore(ChallengeRecord.Purpose purpose, Instant expiresAt) {
    when(challengeStore.takeOnce(CHALLENGE_ID))
        .thenReturn(Optional.of(new ChallengeRecord(CHALLENGE, purpose, USER_HANDLE, expiresAt)));
  }

  private byte[] clientData(String type, String challenge, String origin) {
    var node = jsonMapper.createObjectNode();
    node.put("type", type);
    node.put("challenge", challenge);
    node.put("origin", origin);
    return jsonMapper.writeValueAsString(node).getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] filled(int len, byte v) {
    byte[] out = new byte[len];
    Arrays.fill(out, v);
    return out;
  }
}
