// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class PkAuthJwtTest {

  private static final Instant NOW = Instant.parse("2026-05-13T12:00:00Z");
  private static final String ISSUER = "https://pkauth.example.com";
  private static final String AUDIENCE = "api.example.com";

  @Test
  void hs256RoundTrip() {
    JwtKeyset keyset = JwtKeyset.hs256(randomBytes(32));
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    PkAuthJwtIssuer issuer = new PkAuthJwtIssuer(config, keyset, fixedClock(NOW));
    PkAuthJwtValidator validator = new PkAuthJwtValidator(config, keyset, fixedClock(NOW));

    UserHandle uh = UserHandle.of(new byte[] {1, 2, 3, 4});
    byte[] credId = new byte[] {5, 6, 7, 8};
    JwtClaims claims = JwtClaims.forPasskey(uh, credId, List.of("user", "pwd", "mfa"));

    String token = issuer.issue(claims);
    JwtVerificationResult result = validator.validate(token);

    assertThat(result).isInstanceOf(JwtVerificationResult.Success.class);
    JwtClaims roundTripped = ((JwtVerificationResult.Success) result).claims();
    assertThat(roundTripped.userHandle()).isEqualTo(uh);
    assertThat(roundTripped.method()).isEqualTo(AuthMethod.PASSKEY);
    assertThat(roundTripped.credentialId()).containsExactly(credId);
    assertThat(roundTripped.amr()).containsExactly("user", "pwd", "mfa");
  }

  @Test
  void es256RoundTrip() throws Exception {
    ECKey key = generateEcKey("k1");
    JwtKeyset keyset = JwtKeyset.es256(key);
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    PkAuthJwtIssuer issuer = new PkAuthJwtIssuer(config, keyset, fixedClock(NOW));
    PkAuthJwtValidator validator = new PkAuthJwtValidator(config, keyset, fixedClock(NOW));

    JwtClaims claims = JwtClaims.forBackupCode(UserHandle.of(new byte[] {9, 10}), List.of("user"));
    String token = issuer.issue(claims);
    JwtVerificationResult result = validator.validate(token);

    assertThat(result).isInstanceOf(JwtVerificationResult.Success.class);
  }

  @Test
  void tamperedSignatureIsRejected() {
    JwtKeyset keyset = JwtKeyset.hs256(randomBytes(32));
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    PkAuthJwtIssuer issuer = new PkAuthJwtIssuer(config, keyset, fixedClock(NOW));
    PkAuthJwtValidator validator = new PkAuthJwtValidator(config, keyset, fixedClock(NOW));

    String token =
        issuer.issue(JwtClaims.forMagicLink(UserHandle.of(new byte[] {1}), List.of("user")));
    String tampered = token.substring(0, token.length() - 4) + "AAAA";

    assertThat(validator.validate(tampered))
        .isInstanceOf(JwtVerificationResult.InvalidSignature.class);
  }

  @Test
  void expiredTokenIsRejected() {
    JwtKeyset keyset = JwtKeyset.hs256(randomBytes(32));
    JwtConfig config =
        new JwtConfig(
            ISSUER, AUDIENCE, Duration.ofMinutes(1), Duration.ZERO, Duration.ofSeconds(5));
    PkAuthJwtIssuer issuer = new PkAuthJwtIssuer(config, keyset, fixedClock(NOW));
    String token =
        issuer.issue(JwtClaims.forBackupCode(UserHandle.of(new byte[] {1}), List.of("user")));

    PkAuthJwtValidator later =
        new PkAuthJwtValidator(config, keyset, fixedClock(NOW.plus(Duration.ofMinutes(2))));
    assertThat(later.validate(token)).isInstanceOf(JwtVerificationResult.Expired.class);
  }

  @Test
  void notYetValidIsRejected() {
    JwtKeyset keyset = JwtKeyset.hs256(randomBytes(32));
    // Issue the token with an issuer clock 5 minutes in the future; the validator runs at NOW
    // with a tight clock-skew window, so the embedded nbf falls in the future.
    PkAuthJwtIssuer issuer =
        new PkAuthJwtIssuer(
            JwtConfig.defaults(ISSUER, AUDIENCE),
            keyset,
            fixedClock(NOW.plus(Duration.ofMinutes(5))));
    String token =
        issuer.issue(JwtClaims.forBackupCode(UserHandle.of(new byte[] {1}), List.of("user")));

    JwtConfig validationConfig =
        new JwtConfig(
            ISSUER, AUDIENCE, Duration.ofMinutes(5), Duration.ZERO, Duration.ofSeconds(5));
    PkAuthJwtValidator validator =
        new PkAuthJwtValidator(validationConfig, keyset, fixedClock(NOW));
    assertThat(validator.validate(token)).isInstanceOf(JwtVerificationResult.NotYetValid.class);
  }

  @Test
  void wrongIssuerIsRejected() {
    JwtKeyset keyset = JwtKeyset.hs256(randomBytes(32));
    PkAuthJwtIssuer issuer =
        new PkAuthJwtIssuer(JwtConfig.defaults("other-iss", AUDIENCE), keyset, fixedClock(NOW));
    String token =
        issuer.issue(JwtClaims.forBackupCode(UserHandle.of(new byte[] {1}), List.of("user")));

    PkAuthJwtValidator validator =
        new PkAuthJwtValidator(JwtConfig.defaults(ISSUER, AUDIENCE), keyset, fixedClock(NOW));
    assertThat(validator.validate(token)).isInstanceOf(JwtVerificationResult.WrongIssuer.class);
  }

  @Test
  void wrongAudienceIsRejected() {
    JwtKeyset keyset = JwtKeyset.hs256(randomBytes(32));
    PkAuthJwtIssuer issuer =
        new PkAuthJwtIssuer(JwtConfig.defaults(ISSUER, "other-aud"), keyset, fixedClock(NOW));
    String token =
        issuer.issue(JwtClaims.forBackupCode(UserHandle.of(new byte[] {1}), List.of("user")));

    PkAuthJwtValidator validator =
        new PkAuthJwtValidator(JwtConfig.defaults(ISSUER, AUDIENCE), keyset, fixedClock(NOW));
    assertThat(validator.validate(token)).isInstanceOf(JwtVerificationResult.WrongAudience.class);
  }

  @Test
  void malformedTokenIsRejected() {
    JwtKeyset keyset = JwtKeyset.hs256(randomBytes(32));
    PkAuthJwtValidator validator =
        new PkAuthJwtValidator(JwtConfig.defaults(ISSUER, AUDIENCE), keyset, fixedClock(NOW));
    assertThat(validator.validate("not.a.jwt")).isInstanceOf(JwtVerificationResult.Malformed.class);
  }

  @Test
  void keyRotationAcceptsOlderSignerInVerifySet() throws Exception {
    ECKey oldKey = generateEcKey("old");
    ECKey newKey = generateEcKey("new");
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);

    // Token signed by the OLD key (when it was current).
    JwtKeyset oldKeyset = JwtKeyset.es256(oldKey);
    PkAuthJwtIssuer oldIssuer = new PkAuthJwtIssuer(config, oldKeyset, fixedClock(NOW));
    String token =
        oldIssuer.issue(JwtClaims.forBackupCode(UserHandle.of(new byte[] {1}), List.of("user")));

    // Validator with new+old keyset still accepts the old-signed token.
    JwtKeyset rotated = JwtKeyset.es256(newKey, oldKey);
    PkAuthJwtValidator validator = new PkAuthJwtValidator(config, rotated, fixedClock(NOW));
    assertThat(validator.validate(token)).isInstanceOf(JwtVerificationResult.Success.class);

    // Validator without the old key rejects the same token.
    JwtKeyset newOnly = JwtKeyset.es256(newKey);
    PkAuthJwtValidator newValidator = new PkAuthJwtValidator(config, newOnly, fixedClock(NOW));
    assertThat(newValidator.validate(token))
        .isInstanceOf(JwtVerificationResult.InvalidSignature.class);
  }

  @Test
  void claimsRejectPasskeyMethodWithoutCredentialId() {
    assertThatThrownBy(
            () ->
                new JwtClaims(
                    UserHandle.of(new byte[] {1}), AuthMethod.PASSKEY, null, List.of(), null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void claimsRejectNonPasskeyMethodWithCredentialId() {
    assertThatThrownBy(
            () ->
                new JwtClaims(
                    UserHandle.of(new byte[] {1}),
                    AuthMethod.MAGIC_LINK,
                    new byte[] {1, 2},
                    List.of(),
                    null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void authMethodWireValueMapping() {
    assertThat(AuthMethod.PASSKEY.wireValue()).isEqualTo("passkey");
    assertThat(AuthMethod.BACKUP_CODE.wireValue()).isEqualTo("backup-code");
    assertThat(AuthMethod.MAGIC_LINK.wireValue()).isEqualTo("magic-link");
    assertThat(AuthMethod.fromWireValue("passkey")).isEqualTo(AuthMethod.PASSKEY);
    assertThatThrownBy(() -> AuthMethod.fromWireValue("nope"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void jwtConfigValidations() {
    assertThatThrownBy(
            () -> new JwtConfig("", "a", Duration.ofMinutes(1), Duration.ZERO, Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () -> new JwtConfig("i", "", Duration.ofMinutes(1), Duration.ZERO, Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new JwtConfig("i", "a", Duration.ZERO, Duration.ZERO, Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                new JwtConfig(
                    "i", "a", Duration.ofMinutes(1), Duration.ofSeconds(-1), Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                new JwtConfig(
                    "i", "a", Duration.ofMinutes(1), Duration.ZERO, Duration.ofSeconds(-1)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void keysetSignerAndAlgorithm() {
    JwtKeyset hs = JwtKeyset.hs256(randomBytes(32));
    assertThat(hs.algorithm()).isEqualTo(JWSAlgorithm.HS256);
    assertThat(hs.signer()).isNotNull();
    assertThat(hs.currentKeyId()).isEqualTo("current");
  }

  @Test
  void revokedTokenIsRejected() {
    JwtKeyset keyset = JwtKeyset.hs256(randomBytes(32));
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    PkAuthJwtIssuer issuer = new PkAuthJwtIssuer(config, keyset, fixedClock(NOW));

    String token =
        issuer.issue(JwtClaims.forBackupCode(UserHandle.of(new byte[] {1}), List.of("user")));

    // RevocationCheck that always revokes every token
    RevocationCheck alwaysRevoked = (jti, sub) -> true;
    PkAuthJwtValidator validator =
        new PkAuthJwtValidator(config, keyset, fixedClock(NOW), alwaysRevoked);

    assertThat(validator.validate(token)).isInstanceOf(JwtVerificationResult.Revoked.class);
  }

  @Test
  void defaultAllowRevocationPassesValidToken() {
    JwtKeyset keyset = JwtKeyset.hs256(randomBytes(32));
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    PkAuthJwtIssuer issuer = new PkAuthJwtIssuer(config, keyset, fixedClock(NOW));

    String token =
        issuer.issue(JwtClaims.forBackupCode(UserHandle.of(new byte[] {2}), List.of("user")));

    // No-arg constructor uses RevocationCheck.allow() — token must succeed
    PkAuthJwtValidator validator = new PkAuthJwtValidator(config, keyset, fixedClock(NOW));

    assertThat(validator.validate(token)).isInstanceOf(JwtVerificationResult.Success.class);
  }

  // -- kid-aware validation tests --

  @Test
  void tokenWithMatchingKidValidates() throws Exception {
    ECKey key = generateEcKey("key-1");
    JwtKeyset keyset = JwtKeyset.es256(key);
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    PkAuthJwtIssuer issuer = new PkAuthJwtIssuer(config, keyset, fixedClock(NOW));
    PkAuthJwtValidator validator = new PkAuthJwtValidator(config, keyset, fixedClock(NOW));

    String token =
        issuer.issue(JwtClaims.forBackupCode(UserHandle.of(new byte[] {1}), List.of("user")));
    assertThat(validator.validate(token)).isInstanceOf(JwtVerificationResult.Success.class);
  }

  @Test
  void tokenWithNonExistentKidIsRejectedWithoutFallback() throws Exception {
    ECKey key = generateEcKey("real-key");
    JwtKeyset keyset = JwtKeyset.es256(key);
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    PkAuthJwtValidator validator = new PkAuthJwtValidator(config, keyset, fixedClock(NOW));

    // Build a token that claims kid="no-such-key" but is otherwise structurally valid.
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("no-such-key").build();
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .audience(AUDIENCE)
            .subject(Base64Url.encode(new byte[] {1}))
            .issueTime(Date.from(NOW))
            .notBeforeTime(Date.from(NOW))
            .expirationTime(Date.from(NOW.plus(Duration.ofMinutes(15))))
            .jwtID(UUID.randomUUID().toString())
            .claim(PkAuthJwtIssuer.CLAIM_METHOD, "backup-code")
            .claim(PkAuthJwtIssuer.CLAIM_AMR, List.of("user"))
            .build();
    SignedJWT jwt = new SignedJWT(header, claims);
    jwt.sign(new ECDSASigner(key));

    assertThat(validator.validate(jwt.serialize()))
        .isInstanceOf(JwtVerificationResult.InvalidSignature.class);
  }

  @Test
  void tokenWithoutKidStillValidates() throws Exception {
    ECKey key = generateEcKey(null); // no kid
    JwtKeyset keyset = JwtKeyset.es256(key);
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    PkAuthJwtValidator validator = new PkAuthJwtValidator(config, keyset, fixedClock(NOW));

    // Build a token with no kid header.
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).build();
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .audience(AUDIENCE)
            .subject(Base64Url.encode(new byte[] {1}))
            .issueTime(Date.from(NOW))
            .notBeforeTime(Date.from(NOW))
            .expirationTime(Date.from(NOW.plus(Duration.ofMinutes(15))))
            .jwtID(UUID.randomUUID().toString())
            .claim(PkAuthJwtIssuer.CLAIM_METHOD, "backup-code")
            .claim(PkAuthJwtIssuer.CLAIM_AMR, List.of("user"))
            .build();
    SignedJWT jwt = new SignedJWT(header, claims);
    jwt.sign(new ECDSASigner(key));

    assertThat(validator.validate(jwt.serialize()))
        .isInstanceOf(JwtVerificationResult.Success.class);
  }

  @Test
  void kidlessTokenIsRejectedWhenKeysetHasAnyKidBearingKey() throws Exception {
    // Threat model: an attacker holds a retired key that still lives in the verification keyset
    // for graceful rotation. They forge a token WITHOUT a kid header, signed with the retired key.
    // The validator must NOT iterate every key looking for a match — that would silently accept
    // the retired-key signature and defeat kid-based rotation. As long as the keyset contains at
    // least one key with an assigned kid, a missing kid in the header is itself a rejection.
    ECKey retiredKey = generateEcKey("retired");
    ECKey currentKey = generateEcKey("current");
    JwtKeyset keyset = JwtKeyset.es256(currentKey, retiredKey);
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    PkAuthJwtValidator validator = new PkAuthJwtValidator(config, keyset, fixedClock(NOW));

    // Build a token signed by the retired key but with NO kid header.
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).build();
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .audience(AUDIENCE)
            .subject(Base64Url.encode(new byte[] {1}))
            .issueTime(Date.from(NOW))
            .notBeforeTime(Date.from(NOW))
            .expirationTime(Date.from(NOW.plus(Duration.ofMinutes(15))))
            .jwtID(UUID.randomUUID().toString())
            .claim(PkAuthJwtIssuer.CLAIM_METHOD, "backup-code")
            .claim(PkAuthJwtIssuer.CLAIM_AMR, List.of("user"))
            .build();
    SignedJWT jwt = new SignedJWT(header, claims);
    jwt.sign(new ECDSASigner(retiredKey));

    assertThat(validator.validate(jwt.serialize()))
        .isInstanceOf(JwtVerificationResult.InvalidSignature.class);
  }

  @Test
  void forgedKidClaimIsRejectedWithoutFallingBackToOtherKey() throws Exception {
    // Two keys in the keyset: keyX (kid="key-x") and keyY (kid="key-y").
    // A forged token claims kid="key-x" but is signed with keyY.
    // The validator must NOT fall back to trying keyY — it must reject the token.
    ECKey keyX = generateEcKey("key-x");
    ECKey keyY = generateEcKey("key-y");
    JwtKeyset keyset = JwtKeyset.es256(keyX, keyY);
    JwtConfig config = JwtConfig.defaults(ISSUER, AUDIENCE);
    PkAuthJwtValidator validator = new PkAuthJwtValidator(config, keyset, fixedClock(NOW));

    // Token header claims kid="key-x" but is actually signed by keyY.
    JWSHeader forgedHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("key-x").build();
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .audience(AUDIENCE)
            .subject(Base64Url.encode(new byte[] {1}))
            .issueTime(Date.from(NOW))
            .notBeforeTime(Date.from(NOW))
            .expirationTime(Date.from(NOW.plus(Duration.ofMinutes(15))))
            .jwtID(UUID.randomUUID().toString())
            .claim(PkAuthJwtIssuer.CLAIM_METHOD, "backup-code")
            .claim(PkAuthJwtIssuer.CLAIM_AMR, List.of("user"))
            .build();
    SignedJWT forgedJwt = new SignedJWT(forgedHeader, claims);
    forgedJwt.sign(new ECDSASigner(keyY)); // signed with keyY, not keyX

    assertThat(validator.validate(forgedJwt.serialize()))
        .isInstanceOf(JwtVerificationResult.InvalidSignature.class);
  }

  // -- helpers --

  private static ECKey generateEcKey(String kid) throws Exception {
    if (kid != null) {
      return new ECKeyGenerator(Curve.P_256).keyID(kid).generate();
    }
    return new ECKeyGenerator(Curve.P_256).generate();
  }

  private static byte[] randomBytes(int len) {
    byte[] out = new byte[len];
    new SecureRandom().nextBytes(out);
    return out;
  }

  private static ClockProvider fixedClock(Instant instant) {
    return ClockProvider.fromClock(Clock.fixed(instant, ZoneOffset.UTC));
  }
}
