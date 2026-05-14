// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.demo.dropwizard;

import com.codeheadsystems.pkauth.dropwizard.HasPkAuthConfig;
import com.codeheadsystems.pkauth.dropwizard.config.PkAuthConfig;
import io.dropwizard.core.Configuration;
import java.util.Set;

/**
 * Dropwizard {@link Configuration} for the demo. Hard-codes a working RP / JWT block so the demo
 * runs out of the box with {@code ./gradlew :examples:dropwizard-demo:run}. Production deployments
 * would bind these from a YAML file.
 */
public final class DemoConfiguration extends Configuration implements HasPkAuthConfig {

  private PkAuthConfig pkAuth =
      new PkAuthConfig(
          new PkAuthConfig.RelyingParty(
              "localhost", "pk-auth demo", Set.of("http://localhost:8080")),
          new PkAuthConfig.Jwt("https://issuer.local", "pkauth-demo", defaultDevSecret(), null),
          new PkAuthConfig.Ceremony());

  @Override
  public PkAuthConfig pkAuth() {
    return pkAuth;
  }

  public void setPkAuth(PkAuthConfig pkAuth) {
    this.pkAuth = pkAuth;
  }

  /** 32-byte deterministic dev secret. Never use this in production. */
  static byte[] defaultDevSecret() {
    byte[] secret = new byte[32];
    for (int i = 0; i < secret.length; i++) {
      secret[i] = (byte) ((i * 17 + 3) & 0xff);
    }
    return secret;
  }
}
