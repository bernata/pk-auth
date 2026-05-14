// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.jwt.JwtKeyset;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import io.dropwizard.auth.AuthenticationException;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

final class PasskeyAuthenticatorTest {

  private static final byte[] SECRET = new byte[32];

  static {
    for (int i = 0; i < SECRET.length; i++) SECRET[i] = (byte) (i + 1);
  }

  private PkAuthJwtIssuer issuer;
  private PasskeyAuthenticator authenticator;

  @BeforeEach
  void setUp() {
    JwtConfig cfg = JwtConfig.defaults("iss", "aud");
    JwtKeyset keyset = JwtKeyset.hs256(SECRET);
    ClockProvider clock = ClockProvider.system();
    issuer = new PkAuthJwtIssuer(cfg, keyset, clock);
    PkAuthJwtValidator validator = new PkAuthJwtValidator(cfg, keyset, clock);
    authenticator = new PasskeyAuthenticator(validator);
  }

  @Test
  void validJwtProducesPrincipal() throws AuthenticationException {
    UserHandle handle = UserHandle.random();
    JwtClaims claims =
        JwtClaims.forPasskey(handle, new byte[] {1, 2, 3, 4}, List.of("pkauth", "webauthn"));
    String token = issuer.issue(claims);

    Optional<PasskeyPrincipal> p = authenticator.authenticate(new PasskeyCredentials(token));
    assertThat(p).isPresent();
    assertThat(p.get().userHandle()).isEqualTo(handle);
    assertThat(p.get().getName()).isNotBlank();
    assertThat(p.get().jti()).isEqualTo("verified");
  }

  @Test
  void invalidTokenReturnsEmpty() throws AuthenticationException {
    Optional<PasskeyPrincipal> p = authenticator.authenticate(new PasskeyCredentials("not.a.jwt"));
    assertThat(p).isEmpty();
  }

  @Test
  void tamperedTokenReturnsEmpty() throws AuthenticationException {
    UserHandle handle = UserHandle.random();
    String token = issuer.issue(JwtClaims.forBackupCode(handle, List.of("backup")));
    String tampered = token.substring(0, token.length() - 2) + "AA";
    Optional<PasskeyPrincipal> p = authenticator.authenticate(new PasskeyCredentials(tampered));
    assertThat(p).isEmpty();
  }
}
