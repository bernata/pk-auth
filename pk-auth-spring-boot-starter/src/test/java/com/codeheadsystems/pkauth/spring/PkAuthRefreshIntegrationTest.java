// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.AuthMethod;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.JwtVerificationResult;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.refresh.RefreshTokenPair;
import com.codeheadsystems.pkauth.refresh.RefreshTokenService;
import com.codeheadsystems.pkauth.refresh.web.RefreshRequest;
import com.codeheadsystems.pkauth.refresh.web.RefreshResponse;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import tools.jackson.databind.ObjectMapper;

/**
 * End-to-end refresh test: issue a refresh token via the {@code RefreshTokenService}, present it to
 * {@code POST /auth/refresh}, verify the response carries a new refresh token + a valid access JWT,
 * then replay the original and confirm the family is scorched.
 */
@SpringBootTest(classes = PkAuthTestApplication.class)
class PkAuthRefreshIntegrationTest {

  @Autowired private WebApplicationContext context;
  @Autowired private ObjectMapper objectMapper;
  @Autowired private RefreshTokenService refreshService;
  @Autowired private PkAuthJwtValidator jwtValidator;

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
  }

  @Test
  void rotateMintsValidAccessJwtAndNewRefreshToken() throws Exception {
    RefreshTokenPair root =
        refreshService.issue(
            UserHandle.of(new byte[] {1}), "pk-auth-test-clients", Optional.empty());

    MvcResult result =
        mockMvc
            .perform(
                post("/auth/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(new RefreshRequest(root.wireToken()))))
            .andExpect(status().isOk())
            .andReturn();

    RefreshResponse response =
        objectMapper.readValue(result.getResponse().getContentAsString(), RefreshResponse.class);

    assertThat(response.refreshToken()).isNotBlank().contains(".");
    assertThat(response.refreshToken()).isNotEqualTo(root.wireToken());
    assertThat(response.accessToken()).isNotBlank();

    JwtVerificationResult verified = jwtValidator.validate(response.accessToken());
    assertThat(verified).isInstanceOf(JwtVerificationResult.Success.class);
    JwtClaims claims = ((JwtVerificationResult.Success) verified).claims();
    assertThat(claims.method()).isEqualTo(AuthMethod.REFRESH);
    assertThat(claims.userHandle()).isEqualTo(UserHandle.of(new byte[] {1}));
  }

  @Test
  void replayReturns401Replayed() throws Exception {
    RefreshTokenPair root =
        refreshService.issue(
            UserHandle.of(new byte[] {2}), "pk-auth-test-clients", Optional.empty());

    // First rotation succeeds.
    mockMvc
        .perform(
            post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new RefreshRequest(root.wireToken()))))
        .andExpect(status().isOk());

    // Re-presenting the (now-used) root token is a replay.
    mockMvc
        .perform(
            post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new RefreshRequest(root.wireToken()))))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.detail").value("replayed"));
  }

  @Test
  void unknownWireTokenReturns401Unknown() throws Exception {
    mockMvc
        .perform(
            post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new RefreshRequest("nope.nope"))))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.detail").value("unknown"));
  }
}
