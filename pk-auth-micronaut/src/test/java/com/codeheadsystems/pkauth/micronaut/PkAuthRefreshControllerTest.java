// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.refresh.RefreshTokenPair;
import com.codeheadsystems.pkauth.refresh.RefreshTokenService;
import com.codeheadsystems.pkauth.refresh.web.RefreshRequest;
import com.codeheadsystems.pkauth.refresh.web.RefreshResponse;
import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** Drives the {@code /auth/refresh} endpoint end-to-end through Micronaut's HTTP layer. */
@MicronautTest
@Property(name = "pkauth.relying-party.id", value = "example.com")
@Property(name = "pkauth.relying-party.name", value = "pk-auth micronaut test")
@Property(name = "pkauth.relying-party.origins[0]", value = "https://example.com")
@Property(name = "pkauth.jwt.issuer", value = "https://pkauth.example.com")
@Property(name = "pkauth.jwt.audience", value = "https://app.example.com")
@Property(name = "pkauth.jwt.secret", value = "pk-auth-micronaut-test-secret-32b!")
@Property(name = "pkauth.dev-mode", value = "true")
class PkAuthRefreshControllerTest {

  @Inject
  @Client("/")
  HttpClient client;

  @Inject RefreshTokenService refreshService;

  @Test
  void rotateMintsValidAccessJwtAndNewRefreshToken() {
    RefreshTokenPair root =
        refreshService.issue(
            UserHandle.of(new byte[] {1}), "https://app.example.com", Optional.empty());

    RefreshResponse response =
        client
            .toBlocking()
            .retrieve(
                HttpRequest.POST("/auth/refresh", new RefreshRequest(root.wireToken()))
                    .contentType(MediaType.APPLICATION_JSON),
                RefreshResponse.class);

    assertThat(response.refreshToken()).isNotBlank().contains(".");
    assertThat(response.refreshToken()).isNotEqualTo(root.wireToken());
    assertThat(response.accessToken()).isNotBlank();
  }

  @Test
  void replayReturns401() {
    RefreshTokenPair root =
        refreshService.issue(
            UserHandle.of(new byte[] {2}), "https://app.example.com", Optional.empty());

    // First rotation succeeds.
    client
        .toBlocking()
        .retrieve(
            HttpRequest.POST("/auth/refresh", new RefreshRequest(root.wireToken()))
                .contentType(MediaType.APPLICATION_JSON),
            RefreshResponse.class);

    // Re-presenting the used root token → 401.
    assertThatThrownBy(
            () ->
                client
                    .toBlocking()
                    .retrieve(
                        HttpRequest.POST("/auth/refresh", new RefreshRequest(root.wireToken()))
                            .contentType(MediaType.APPLICATION_JSON),
                        RefreshResponse.class))
        .isInstanceOfSatisfying(
            HttpClientResponseException.class,
            e -> assertThat((Object) e.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED));
  }
}
