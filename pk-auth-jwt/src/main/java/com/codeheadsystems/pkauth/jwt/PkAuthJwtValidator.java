// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Validates pk-auth JWTs produced by {@link PkAuthJwtIssuer}. Separate from issuance so adapter
 * modules can take this class without pulling in signing keys.
 */
public final class PkAuthJwtValidator {

  private final JwtConfig config;
  private final JwtKeyset keyset;
  private final ClockProvider clockProvider;

  public PkAuthJwtValidator(JwtConfig config, JwtKeyset keyset, ClockProvider clockProvider) {
    this.config = Objects.requireNonNull(config, "config");
    this.keyset = Objects.requireNonNull(keyset, "keyset");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
  }

  /** Verifies signature and standard claims, then reconstructs a {@link JwtClaims}. */
  public JwtVerificationResult validate(String token) {
    Objects.requireNonNull(token, "token");
    SignedJWT jwt;
    try {
      jwt = SignedJWT.parse(token);
    } catch (ParseException e) {
      return new JwtVerificationResult.Malformed("unparseable: " + e.getMessage());
    }

    JWSAlgorithm alg = jwt.getHeader().getAlgorithm();
    if (alg == null || !alg.equals(keyset.algorithm())) {
      return new JwtVerificationResult.InvalidSignature();
    }

    if (!verifyAgainstAnyKey(jwt)) {
      return new JwtVerificationResult.InvalidSignature();
    }

    JWTClaimsSet body;
    try {
      body = jwt.getJWTClaimsSet();
    } catch (ParseException e) {
      return new JwtVerificationResult.Malformed("invalid claims set: " + e.getMessage());
    }

    if (!config.issuer().equals(body.getIssuer())) {
      return new JwtVerificationResult.WrongIssuer(
          config.issuer(), body.getIssuer() == null ? "" : body.getIssuer());
    }

    List<String> aud = body.getAudience();
    if (aud == null || !aud.contains(config.audience())) {
      return new JwtVerificationResult.WrongAudience(
          config.audience(), aud == null ? "" : String.join(",", aud));
    }

    Instant now = clockProvider.now();
    Date exp = body.getExpirationTime();
    if (exp == null) {
      return new JwtVerificationResult.MissingClaim("exp");
    }
    if (now.isAfter(exp.toInstant().plus(config.clockSkew()))) {
      return new JwtVerificationResult.Expired(exp.toInstant());
    }

    Date nbf = body.getNotBeforeTime();
    if (nbf != null && now.isBefore(nbf.toInstant().minus(config.clockSkew()))) {
      return new JwtVerificationResult.NotYetValid(nbf.toInstant());
    }

    String subject = body.getSubject();
    if (subject == null || subject.isEmpty()) {
      return new JwtVerificationResult.MissingClaim("sub");
    }
    UserHandle userHandle;
    try {
      userHandle = UserHandle.of(Base64Url.decode(subject));
    } catch (RuntimeException e) {
      return new JwtVerificationResult.Malformed("invalid sub: " + e.getMessage());
    }

    String methodClaim = stringClaim(body, PkAuthJwtIssuer.CLAIM_METHOD);
    if (methodClaim == null) {
      return new JwtVerificationResult.MissingClaim(PkAuthJwtIssuer.CLAIM_METHOD);
    }
    AuthMethod method;
    try {
      method = AuthMethod.fromWireValue(methodClaim);
    } catch (IllegalArgumentException e) {
      return new JwtVerificationResult.Malformed("unknown pkauth.method: " + methodClaim);
    }

    byte @Nullable [] credentialId = null;
    String credClaim = stringClaim(body, PkAuthJwtIssuer.CLAIM_CRED);
    if (method == AuthMethod.PASSKEY) {
      if (credClaim == null) {
        return new JwtVerificationResult.MissingClaim(PkAuthJwtIssuer.CLAIM_CRED);
      }
      try {
        credentialId = Base64Url.decode(credClaim);
      } catch (RuntimeException e) {
        return new JwtVerificationResult.Malformed("invalid pkauth.cred: " + e.getMessage());
      }
    } else if (credClaim != null) {
      return new JwtVerificationResult.Malformed(
          "pkauth.cred must not appear when pkauth.method != passkey");
    }

    List<String> amr = stringListClaim(body, PkAuthJwtIssuer.CLAIM_AMR);
    if (amr == null) {
      amr = List.of();
    }

    Map<String, Object> remaining = removeKnownClaims(body.toJSONObject());
    return new JwtVerificationResult.Success(
        new JwtClaims(
            userHandle, method, credentialId, amr, remaining.isEmpty() ? null : remaining));
  }

  private boolean verifyAgainstAnyKey(SignedJWT jwt) {
    // We already checked alg against the keyset; trust every key in the set and let Nimbus's
    // verifier reject mismatches. Filtering by `algorithm` here would skip keys whose
    // `algorithm()` is null (the common case for ECKeyGenerator output).
    JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().build());
    List<JWK> candidates;
    try {
      candidates = keyset.verificationSource().get(selector, (SecurityContext) null);
    } catch (com.nimbusds.jose.KeySourceException | RuntimeException e) {
      return false;
    }
    for (JWK candidate : candidates) {
      JWSVerifier verifier;
      try {
        if (candidate instanceof OctetSequenceKey oct) {
          verifier = new MACVerifier(oct);
        } else if (candidate instanceof ECKey ec) {
          verifier = new ECDSAVerifier(ec);
        } else {
          continue;
        }
        if (jwt.verify(verifier)) {
          return true;
        }
      } catch (JOSEException e) {
        // try next key
      }
    }
    return false;
  }

  private static @Nullable String stringClaim(JWTClaimsSet body, String name) {
    try {
      return body.getStringClaim(name);
    } catch (ParseException e) {
      return null;
    }
  }

  private static @Nullable List<String> stringListClaim(JWTClaimsSet body, String name) {
    try {
      return body.getStringListClaim(name);
    } catch (ParseException e) {
      return null;
    }
  }

  private static Map<String, Object> removeKnownClaims(Map<String, Object> raw) {
    Map<String, Object> copy = new java.util.LinkedHashMap<>(raw);
    copy.remove("iss");
    copy.remove("sub");
    copy.remove("aud");
    copy.remove("iat");
    copy.remove("nbf");
    copy.remove("exp");
    copy.remove("jti");
    copy.remove(PkAuthJwtIssuer.CLAIM_METHOD);
    copy.remove(PkAuthJwtIssuer.CLAIM_CRED);
    copy.remove(PkAuthJwtIssuer.CLAIM_AMR);
    return copy;
  }
}
