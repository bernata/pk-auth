// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.AuthMethod;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.spring.security.PkAuthJwtAuthenticationToken;
import java.util.List;
import org.junit.jupiter.api.Test;

class PkAuthJwtAuthenticationTokenTest {

  @Test
  void principalAndClaimsRoundTrip() {
    UserHandle handle = UserHandle.random();
    JwtClaims claims = JwtClaims.forBackupCode(handle, List.of("bckp"));
    PkAuthJwtAuthenticationToken token =
        new PkAuthJwtAuthenticationToken(handle, claims, "raw-token");

    assertThat(token.isAuthenticated()).isTrue();
    assertThat(token.getPrincipal()).isEqualTo(handle);
    assertThat(token.getCredentials()).isEqualTo("raw-token");
    assertThat(token.getToken()).isEqualTo("raw-token");
    assertThat(token.getClaims()).isEqualTo(claims);
    assertThat(token.getAuthorities())
        .extracting(a -> a.getAuthority())
        .containsExactlyInAnyOrder("ROLE_USER", "PKAUTH_METHOD_" + AuthMethod.BACKUP_CODE.name());
  }
}
