// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.spi.UserLookup;
import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

/** Drives authenticated admin endpoints with a freshly-minted JWT. */
@MicronautTest
@Property(name = "pkauth.relying-party.id", value = "example.com")
@Property(name = "pkauth.relying-party.name", value = "test")
@Property(name = "pkauth.relying-party.origins[0]", value = "https://example.com")
@Property(name = "pkauth.jwt.issuer", value = "https://pkauth.example.com")
@Property(name = "pkauth.jwt.audience", value = "https://app.example.com")
@Property(name = "pkauth.jwt.secret", value = "pk-auth-micronaut-test-secret-32b!")
@Property(name = "pkauth.dev-mode", value = "true")
class PkAuthAdminAuthenticatedTest {

  @Inject
  @Client("/")
  HttpClient client;

  @Inject PkAuthJwtIssuer issuer;
  @Inject UserLookup users;

  @Test
  void getAccountWithValidJwt() {
    UserHandle uh = users.getOrCreateHandle("alice");
    String token = issuer.issue(JwtClaims.forBackupCode(uh, List.of("test")));

    HttpResponse<String> response =
        client
            .toBlocking()
            .exchange(HttpRequest.GET("/auth/admin/account").bearerAuth(token), String.class);
    Assertions.assertThat(response.getStatus().getCode()).isEqualTo(HttpStatus.OK.getCode());
    Assertions.assertThat(response.body()).contains("alice");
  }

  @Test
  void regenerateBackupCodesIssuesPlaintext() {
    UserHandle uh = users.getOrCreateHandle("bob");
    String token = issuer.issue(JwtClaims.forBackupCode(uh, List.of("test")));

    HttpResponse<String> response =
        client
            .toBlocking()
            .exchange(
                HttpRequest.POST("/auth/admin/backup-codes/regenerate", "")
                    .bearerAuth(token)
                    .contentType(MediaType.APPLICATION_JSON),
                String.class);
    Assertions.assertThat(response.getStatus().getCode()).isEqualTo(HttpStatus.OK.getCode());
    Assertions.assertThat(response.body()).contains("codes");
  }

  @Test
  void startPhoneVerificationDispatches() {
    UserHandle uh = users.getOrCreateHandle("carol");
    String token = issuer.issue(JwtClaims.forBackupCode(uh, List.of("test")));

    HttpResponse<String> response =
        client
            .toBlocking()
            .exchange(
                HttpRequest.POST(
                        "/auth/admin/phone/start-verification", "{\"phone\":\"+15551234567\"}")
                    .bearerAuth(token)
                    .contentType(MediaType.APPLICATION_JSON),
                String.class);
    Assertions.assertThat(response.getStatus().getCode()).isEqualTo(HttpStatus.OK.getCode());
    Assertions.assertThat(response.body()).contains("otpId");
  }
}
