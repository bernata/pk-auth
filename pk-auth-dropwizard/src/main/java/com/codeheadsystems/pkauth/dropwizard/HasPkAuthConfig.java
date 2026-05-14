// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard;

import com.codeheadsystems.pkauth.dropwizard.config.PkAuthConfig;

/**
 * Marker interface a host application's Dropwizard {@code Configuration} class implements so the
 * {@link PkAuthBundle} can pull its config block out at {@code run()} time. Brief §6.11.
 */
public interface HasPkAuthConfig {
  /** The pk-auth configuration block (relying-party identity, JWT keys, ceremony policy). */
  PkAuthConfig pkAuth();
}
