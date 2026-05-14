// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.json;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

final class PkAuthJacksonBridgeTest {

  private final ObjectMapper mapper = PkAuthJacksonBridge.register(new ObjectMapper());

  @Test
  void bytesRoundTripAsBase64Url() throws Exception {
    byte[] bytes = new byte[] {0, 1, 2, 3, (byte) 255};
    String json = mapper.writeValueAsString(bytes);
    assertThat(json).isEqualTo("\"" + Base64Url.encode(bytes) + "\"");
    byte[] back = mapper.readValue(json, byte[].class);
    assertThat(back).containsExactly(bytes);
  }

  @Test
  void userHandleRoundTripsAsBase64Url() throws Exception {
    UserHandle handle = UserHandle.of(new byte[] {1, 2, 3, 4});
    String json = mapper.writeValueAsString(handle);
    assertThat(json).isEqualTo("\"" + Base64Url.encode(handle.value()) + "\"");
    UserHandle back = mapper.readValue(json, UserHandle.class);
    assertThat(back).isEqualTo(handle);
  }

  @Test
  void challengeIdRoundTripsAsRawString() throws Exception {
    ChallengeId id = new ChallengeId("abc-123");
    String json = mapper.writeValueAsString(id);
    assertThat(json).isEqualTo("\"abc-123\"");
    ChallengeId back = mapper.readValue(json, ChallengeId.class);
    assertThat(back).isEqualTo(id);
  }
}
