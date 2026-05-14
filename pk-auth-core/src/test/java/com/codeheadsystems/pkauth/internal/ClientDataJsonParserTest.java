// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.internal;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.json.Base64Url;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ClientDataJsonParserTest {

  @Test
  void parsesTypeChallengeAndOrigin() {
    byte[] challengeBytes = {1, 2, 3};
    String json =
        "{\"type\":\"webauthn.create\",\"challenge\":\""
            + Base64Url.encode(challengeBytes)
            + "\",\"origin\":\"https://example.com\"}";

    ClientDataJsonParser.ClientData cd =
        ClientDataJsonParser.parse(json.getBytes(StandardCharsets.UTF_8));

    assertThat(cd.type()).isEqualTo("webauthn.create");
    assertThat(cd.origin()).isEqualTo("https://example.com");
    assertThat(cd.challengeBytes()).containsExactly(1, 2, 3);
  }

  @Test
  void challengeBytesDecodesAdditionalFields() {
    // Real clientDataJSON often includes more than type/challenge/origin. The parser must ignore
    // those extras (FAIL_ON_UNKNOWN_PROPERTIES is intentionally disabled for this internal parser).
    String json =
        "{\"type\":\"webauthn.get\",\"challenge\":\"AAA\",\"origin\":\"https://x\",\"crossOrigin\":false}";
    ClientDataJsonParser.ClientData cd =
        ClientDataJsonParser.parse(json.getBytes(StandardCharsets.UTF_8));
    assertThat(cd.type()).isEqualTo("webauthn.get");
  }
}
