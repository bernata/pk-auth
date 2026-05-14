// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Issues pk-auth JWTs. Maps {@link JwtClaims} onto the standard {@code iss/sub/aud/iat/nbf/exp/jti}
 * claims plus {@code pkauth.method}, {@code pkauth.cred}, {@code pkauth.amr}.
 */
public final class PkAuthJwtIssuer {

  /** Header value for the pk-auth method claim. */
  public static final String CLAIM_METHOD = "pkauth.method";

  /**
   * Header value for the pk-auth credential id claim (base64url string, present only for passkeys).
   */
  public static final String CLAIM_CRED = "pkauth.cred";

  /** Header value for the pk-auth authentication method reference array. */
  public static final String CLAIM_AMR = "pkauth.amr";

  private final JwtConfig config;
  private final JwtKeyset keyset;
  private final ClockProvider clockProvider;

  public PkAuthJwtIssuer(JwtConfig config, JwtKeyset keyset, ClockProvider clockProvider) {
    this.config = Objects.requireNonNull(config, "config");
    this.keyset = Objects.requireNonNull(keyset, "keyset");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
  }

  /** Issues a signed JWT for the supplied claims. */
  public String issue(JwtClaims claims) {
    Objects.requireNonNull(claims, "claims");
    Instant now = clockProvider.now();
    JWTClaimsSet.Builder body =
        new JWTClaimsSet.Builder()
            .issuer(config.issuer())
            .audience(config.audience())
            .subject(Base64Url.encode(claims.userHandle().value()))
            .issueTime(Date.from(now))
            .notBeforeTime(Date.from(now.minus(config.notBeforeSkew())))
            .expirationTime(Date.from(now.plus(config.tokenTtl())))
            .jwtID(UUID.randomUUID().toString())
            .claim(CLAIM_METHOD, claims.method().wireValue())
            .claim(CLAIM_AMR, List.copyOf(claims.amr()));

    byte[] credId = claims.credentialId();
    if (credId != null) {
      body.claim(CLAIM_CRED, Base64Url.encode(credId));
    }

    if (claims.additionalClaims() != null) {
      for (Map.Entry<String, Object> e : claims.additionalClaims().entrySet()) {
        body.claim(e.getKey(), e.getValue());
      }
    }

    JWSHeader header =
        new JWSHeader.Builder(keyset.algorithm()).keyID(keyset.currentKeyId()).build();
    SignedJWT jwt = new SignedJWT(header, body.build());
    try {
      jwt.sign(keyset.signer());
    } catch (JOSEException e) {
      throw new IllegalStateException("Failed to sign JWT", e);
    }
    return jwt.serialize();
  }
}
