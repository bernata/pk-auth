// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.jwt;

import com.codeheadsystems.pkauth.api.AssertionResult;
import java.util.List;
import java.util.Objects;

/**
 * Shared JWT-minting helper used by every adapter (Spring, Dropwizard, Micronaut) immediately after
 * a successful WebAuthn assertion. Before this helper existed each adapter constructed {@link
 * JwtClaims#forPasskey} inline, with a different {@code amr} list per adapter; this helper
 * standardizes the claim shape so a token minted by the Spring adapter is byte-equivalent (modulo
 * {@code jti}/{@code iat}) to one minted by Dropwizard or Micronaut.
 *
 * <p><b>Standardized {@code amr}</b>: {@link #ASSERTION_AMR} — {@code ["pkauth", "webauthn"]}. The
 * RFC 8176 registry doesn't define a passkey-specific token, so we use the descriptive {@code
 * "pkauth"} (the library tag) plus the standard {@code "webauthn"} that consumers can recognise.
 *
 * <p>This helper deliberately takes no {@code CredentialRepository} — the credential label is the
 * adapter's concern (it appears in the HTTP response body, not the JWT), so the adapter looks it up
 * once when it needs it, NOT through this helper.
 */
public final class PkAuthCeremonyJwt {

  /** Authentication method reference array embedded in every passkey-issued JWT. */
  public static final List<String> ASSERTION_AMR = List.of("pkauth", "webauthn");

  private PkAuthCeremonyJwt() {}

  /**
   * Mints a JWT for a successful WebAuthn assertion. The subject, credential id, and amr list are
   * derived from {@code success}; the issuer/audience/ttl come from the {@link PkAuthJwtIssuer}'s
   * configured {@link JwtConfig}.
   *
   * @param success the successful assertion outcome from the ceremony service.
   * @param issuer the configured JWT issuer.
   * @return a signed pk-auth JWT.
   */
  public static String mintForAssertion(AssertionResult.Success success, PkAuthJwtIssuer issuer) {
    Objects.requireNonNull(success, "success");
    Objects.requireNonNull(issuer, "issuer");
    JwtClaims claims =
        JwtClaims.forPasskey(success.userHandle(), success.credentialId().value(), ASSERTION_AMR);
    return issuer.issue(claims);
  }
}
