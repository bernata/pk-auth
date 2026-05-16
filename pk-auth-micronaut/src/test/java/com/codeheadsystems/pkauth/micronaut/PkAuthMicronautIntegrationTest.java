// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.testkit.FakeAuthenticator;
import com.codeheadsystems.pkauth.testkit.PkAuthFixtures;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.util.ObjectConverter;
import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

/** Drives a full registration → assertion ceremony through the Micronaut HTTP layer. */
@MicronautTest
@Property(name = "pkauth.relying-party.id", value = "example.com")
@Property(name = "pkauth.relying-party.name", value = "pk-auth micronaut test")
@Property(name = "pkauth.relying-party.origins[0]", value = "https://example.com")
@Property(name = "pkauth.jwt.issuer", value = "https://pkauth.example.com")
@Property(name = "pkauth.jwt.audience", value = "https://app.example.com")
@Property(name = "pkauth.jwt.secret", value = "pk-auth-micronaut-test-secret-32b!")
@Property(name = "pkauth.dev-mode", value = "true")
class PkAuthMicronautIntegrationTest {

  @Inject
  @Client("/")
  HttpClient client;

  @Inject ObjectMapper mapper;

  @Test
  void registerThenAssertProducesJwt() throws Exception {
    FakeAuthenticator authenticator =
        FakeAuthenticator.builder()
            .origin(PkAuthFixtures.DEFAULT_ORIGIN)
            .rpId(PkAuthFixtures.DEFAULT_RP_ID)
            .objectConverter(new ObjectConverter())
            .build();

    // Start registration.
    StartRegistrationResponse startReg =
        client
            .toBlocking()
            .retrieve(
                HttpRequest.POST(
                        "/auth/passkeys/registration/start",
                        new StartRegistrationRequest("alice", "Alice", null, null))
                    .contentType(MediaType.APPLICATION_JSON),
                StartRegistrationResponse.class);
    assertThat(startReg.challengeId()).isNotNull();

    // Finish registration. Sealed RegistrationResult / AssertionResult are awkward to
    // deserialize on the client without type info, so the test inspects the raw JSON.
    RegistrationResponseJson regResp = authenticator.createRegistrationResponse(startReg);
    String regBody =
        client
            .toBlocking()
            .retrieve(
                HttpRequest.POST(
                        "/auth/passkeys/registration/finish",
                        new FinishRegistrationRequest(
                            startReg.challengeId(), "alice", "Test key", regResp))
                    .contentType(MediaType.APPLICATION_JSON),
                String.class);
    assertThat(regBody).contains("\"outcome\":\"success\"").contains("\"userHandle\"");
    var regJson = mapper.readTree(regBody);
    UserHandle handle = UserHandle.of(Base64Url.decode(regJson.path("userHandle").asText()));

    // Start authentication.
    StartAuthenticationResponse startAuth =
        client
            .toBlocking()
            .retrieve(
                HttpRequest.POST(
                        "/auth/passkeys/authentication/start",
                        new StartAuthenticationRequest("alice", null))
                    .contentType(MediaType.APPLICATION_JSON),
                StartAuthenticationResponse.class);
    assertThat(startAuth.challengeId()).isNotNull();

    // Finish authentication — assert the JWT is returned.
    AuthenticationResponseJson authResp = authenticator.createAssertionResponse(startAuth, handle);
    String authBody =
        client
            .toBlocking()
            .retrieve(
                HttpRequest.POST(
                        "/auth/passkeys/authentication/finish",
                        new FinishAuthenticationRequest(startAuth.challengeId(), authResp))
                    .contentType(MediaType.APPLICATION_JSON),
                String.class);
    var authJson = mapper.readTree(authBody);
    assertThat(authJson.has("token")).isTrue();
    assertThat(authJson.path("token").asText()).isNotBlank();
  }
}
