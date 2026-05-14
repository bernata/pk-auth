// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard;

import com.codeheadsystems.pkauth.dropwizard.config.PkAuthConfig;
import io.dropwizard.core.Configuration;
import java.util.Objects;

/** Test-only Dropwizard {@link Configuration} carrying a {@link PkAuthConfig} block. */
public final class TestConfiguration extends Configuration implements HasPkAuthConfig {

  private PkAuthConfig pkAuth;

  public TestConfiguration() {}

  public TestConfiguration(PkAuthConfig pkAuth) {
    this.pkAuth = Objects.requireNonNull(pkAuth);
  }

  @Override
  public PkAuthConfig pkAuth() {
    return pkAuth;
  }

  /** Setter so Dropwizard's YAML binder can populate the field reflectively in tests. */
  public void setPkAuth(PkAuthConfig pkAuth) {
    this.pkAuth = pkAuth;
  }
}
