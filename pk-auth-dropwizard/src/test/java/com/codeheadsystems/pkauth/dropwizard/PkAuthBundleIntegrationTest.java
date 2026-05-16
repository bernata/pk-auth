// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.admin.AccountSummary;
import com.codeheadsystems.pkauth.admin.BackupCodesGenerated;
import com.codeheadsystems.pkauth.admin.CredentialSummary;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.dropwizard.config.PkAuthConfig;
import com.codeheadsystems.pkauth.dropwizard.json.PkAuthJacksonBridge;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.jwt.JwtVerificationResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.jakarta.rs.json.JacksonJsonProvider;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.GenericType;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * End-to-end integration test driving the {@link PkAuthBundle} via {@link DropwizardAppExtension}.
 * Uses the testkit's {@code FakeAuthenticator} to round-trip a real WebAuthn ceremony through
 * Jersey, then exercises the JWT validator and a couple of admin endpoints.
 */
@ExtendWith(DropwizardExtensionsSupport.class)
final class PkAuthBundleIntegrationTest {

  private static final byte[] HS256_SECRET = new byte[32];

  static {
    // Deterministic non-zero secret so JWT signatures across the wire look like real ones.
    for (int i = 0; i < HS256_SECRET.length; i++) {
      HS256_SECRET[i] = (byte) (i + 1);
    }
  }

  private final TestApplication.State state;

  {
    state = new TestApplication.State();
    TestApplication.ACTIVE.set(state);
  }

  private final DropwizardAppExtension<TestConfiguration> app =
      new DropwizardAppExtension<>(
          TestApplication.class,
          new TestConfiguration(
              new PkAuthConfig(
                  new PkAuthConfig.RelyingParty(
                      "example.com", "pk-auth test", Set.of("https://example.com")),
                  new PkAuthConfig.Jwt("https://issuer.example", "demo-aud", HS256_SECRET, null),
                  new PkAuthConfig.Ceremony())));

  private Client client;
  private String baseUrl;

  @BeforeEach
  void setUp() {
    // Reuse Dropwizard's environment ObjectMapper (with the pk-auth bridge registered) so the
    // client and server agree on every pk-auth value type. ClientBuilder.newClient() would build
    // a fresh mapper that doesn't have JavaTimeModule etc.
    ObjectMapper mapper = PkAuthJacksonBridge.register(app.getObjectMapper().copy());
    JacksonJsonProvider provider = new JacksonJsonProvider(mapper);
    client = ClientBuilder.newBuilder().register(provider).build();
    baseUrl = "http://localhost:" + app.getLocalPort();
  }

  @AfterEach
  void tearDown() {
    if (client != null) {
      client.close();
    }
  }

  @Test
  void registerAndAuthenticateOverHttpReturnsValidJwt() {
    // -- Register --------------------------------------------------------------------------
    StartRegistrationResponse regStart =
        post(
            "/auth/passkeys/registration/start",
            new StartRegistrationRequest("alice", "Alice", "Test key", null),
            StartRegistrationResponse.class);
    assertThat(regStart.publicKey()).isNotNull();

    RegistrationResponseJson regResp =
        state.everything.authenticator.createRegistrationResponse(regStart);
    Response finishReg =
        client
            .target(baseUrl + "/auth/passkeys/registration/finish")
            .request(MediaType.APPLICATION_JSON)
            .post(
                Entity.json(
                    new FinishRegistrationRequest(
                        regStart.challengeId(), "alice", "Test key", regResp)));
    assertThat(finishReg.getStatus()).isEqualTo(200);
    Map<String, Object> regBody = finishReg.readEntity(new GenericType<Map<String, Object>>() {});
    assertThat(regBody).containsEntry("outcome", "success").containsEntry("label", "Test key");
    UserHandle userHandle = UserHandle.of(Base64Url.decode((String) regBody.get("userHandle")));

    // -- Authenticate ----------------------------------------------------------------------
    StartAuthenticationResponse authStart =
        post(
            "/auth/passkeys/authentication/start",
            new StartAuthenticationRequest("alice", null),
            StartAuthenticationResponse.class);
    AuthenticationResponseJson authResp =
        state.everything.authenticator.createAssertionResponse(authStart, userHandle);
    Response authResponse =
        client
            .target(baseUrl + "/auth/passkeys/authentication/finish")
            .request(MediaType.APPLICATION_JSON)
            .post(Entity.json(new FinishAuthenticationRequest(authStart.challengeId(), authResp)));
    assertThat(authResponse.getStatus()).isEqualTo(200);
    Map<String, Object> authBody = authResponse.readEntity(new GenericType<>() {});
    assertThat(authBody).containsEntry("outcome", "success");
    String token = (String) authBody.get("token");
    assertThat(token).isNotBlank();

    // -- Validate JWT ----------------------------------------------------------------------
    JwtVerificationResult validation = state.bundle.jwtValidator().validate(token);
    assertThat(validation).isInstanceOf(JwtVerificationResult.Success.class);
    JwtVerificationResult.Success vs = (JwtVerificationResult.Success) validation;
    assertThat(vs.claims().userHandle()).isEqualTo(userHandle);

    // -- Admin: account summary ------------------------------------------------------------
    AccountSummary acct = get("/auth/admin/account", token, AccountSummary.class);
    assertThat(acct.userHandle()).isEqualTo(userHandle);
    assertThat(acct.credentialCount()).isEqualTo(1);

    // -- Admin: list credentials -----------------------------------------------------------
    List<CredentialSummary> creds =
        getList("/auth/admin/credentials", token, new GenericType<>() {});
    assertThat(creds).hasSize(1);
    assertThat(creds.get(0).label()).isEqualTo("Test key");

    // -- Admin: regenerate backup codes ----------------------------------------------------
    BackupCodesGenerated codes =
        client
            .target(baseUrl + "/auth/admin/backup-codes/regenerate")
            .request(MediaType.APPLICATION_JSON)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .post(Entity.json(""), BackupCodesGenerated.class);
    assertThat(codes.codes()).hasSize(10);
  }

  @Test
  void missingBearerOnAdminEndpointReturns401() {
    Response r =
        client.target(baseUrl + "/auth/admin/account").request(MediaType.APPLICATION_JSON).get();
    assertThat(r.getStatus()).isEqualTo(401);
  }

  @Test
  void invalidBearerReturns401() {
    Response r =
        client
            .target(baseUrl + "/auth/admin/account")
            .request(MediaType.APPLICATION_JSON)
            .header(HttpHeaders.AUTHORIZATION, "Bearer notavalidtoken")
            .get();
    assertThat(r.getStatus()).isEqualTo(401);
  }

  @Test
  void componentExposesIssuerAndValidator() {
    assertThat(state.bundle.jwtIssuer()).isNotNull();
    assertThat(state.bundle.jwtValidator()).isNotNull();
    assertThat(state.bundle.component().passkeyAuthenticator()).isNotNull();
  }

  private <T> T post(String path, Object body, Class<T> type) {
    Response r =
        client.target(baseUrl + path).request(MediaType.APPLICATION_JSON).post(Entity.json(body));
    if (r.getStatus() >= 400) {
      String text = r.readEntity(String.class);
      throw new AssertionError("POST " + path + " returned " + r.getStatus() + " body=" + text);
    }
    return r.readEntity(type);
  }

  private <T> T get(String path, String token, Class<T> type) {
    Response r =
        client
            .target(baseUrl + path)
            .request(MediaType.APPLICATION_JSON)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .get();
    if (r.getStatus() >= 400) {
      String text = r.readEntity(String.class);
      throw new AssertionError("GET " + path + " returned " + r.getStatus() + " body=" + text);
    }
    return r.readEntity(type);
  }

  private <T> T getList(String path, String token, GenericType<T> type) {
    Response r =
        client
            .target(baseUrl + path)
            .request(MediaType.APPLICATION_JSON)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .get();
    if (r.getStatus() >= 400) {
      String text = r.readEntity(String.class);
      throw new AssertionError("GET " + path + " returned " + r.getStatus() + " body=" + text);
    }
    return r.readEntity(type);
  }

  // Reference the ObjectMapper field so the import is used (Jackson 2 mapper retrieval keeps the
  // bridge wired up — see PkAuthJacksonBridge).
  @SuppressWarnings("unused")
  private ObjectMapper mapper() {
    return app.getObjectMapper();
  }
}
