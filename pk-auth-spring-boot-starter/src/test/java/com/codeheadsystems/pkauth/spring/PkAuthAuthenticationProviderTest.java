// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.AuthMethod;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.jwt.JwtKeyset;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spring.security.JwtAuthenticationToken;
import com.codeheadsystems.pkauth.spring.security.PkAuthAuthenticationProvider;
import com.codeheadsystems.pkauth.spring.security.PreAuthenticatedJwtToken;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

class PkAuthAuthenticationProviderTest {

  private static byte[] secret() {
    byte[] bytes = new byte[32];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) i;
    }
    return bytes;
  }

  @Test
  void authenticateValidTokenReturnsJwtAuthenticationToken() {
    JwtConfig config = JwtConfig.defaults("iss", "aud");
    JwtKeyset keyset = JwtKeyset.hs256(secret());
    ClockProvider clock = ClockProvider.system();
    PkAuthJwtIssuer issuer = new PkAuthJwtIssuer(config, keyset, clock);
    PkAuthJwtValidator validator = new PkAuthJwtValidator(config, keyset, clock);
    PkAuthAuthenticationProvider provider = new PkAuthAuthenticationProvider(validator);

    UserHandle handle = UserHandle.random();
    String token =
        issuer.issue(new JwtClaims(handle, AuthMethod.BACKUP_CODE, null, List.of("bckp"), null));

    Authentication auth = provider.authenticate(new PreAuthenticatedJwtToken(token));
    assertThat(auth).isInstanceOf(JwtAuthenticationToken.class);
    assertThat(((JwtAuthenticationToken) auth).getPrincipal()).isEqualTo(handle);
  }

  @Test
  void authenticateBogusTokenThrowsBadCredentials() {
    JwtConfig config = JwtConfig.defaults("iss", "aud");
    JwtKeyset keyset = JwtKeyset.hs256(secret());
    PkAuthJwtValidator validator = new PkAuthJwtValidator(config, keyset, ClockProvider.system());
    PkAuthAuthenticationProvider provider = new PkAuthAuthenticationProvider(validator);

    assertThatThrownBy(() -> provider.authenticate(new PreAuthenticatedJwtToken("not-a-jwt")))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void unsupportedAuthenticationTypeReturnsNull() {
    PkAuthJwtValidator validator =
        new PkAuthJwtValidator(
            JwtConfig.defaults("iss", "aud"), JwtKeyset.hs256(secret()), ClockProvider.system());
    PkAuthAuthenticationProvider provider = new PkAuthAuthenticationProvider(validator);
    assertThat(provider.supports(UsernamePasswordAuthenticationToken.class)).isFalse();
    Authentication ignored =
        provider.authenticate(new UsernamePasswordAuthenticationToken("a", "b"));
    assertThat(ignored).isNull();
  }
}
