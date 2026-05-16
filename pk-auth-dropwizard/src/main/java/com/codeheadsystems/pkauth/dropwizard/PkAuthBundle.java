// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard;

import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.dropwizard.admin.AdminResource;
import com.codeheadsystems.pkauth.dropwizard.auth.PasskeyAuthFilter;
import com.codeheadsystems.pkauth.dropwizard.auth.PasskeyAuthenticator;
import com.codeheadsystems.pkauth.dropwizard.auth.PasskeyPrincipal;
import com.codeheadsystems.pkauth.dropwizard.dagger.DaggerPkAuthComponent;
import com.codeheadsystems.pkauth.dropwizard.dagger.PersistenceBindings;
import com.codeheadsystems.pkauth.dropwizard.dagger.PkAuthComponent;
import com.codeheadsystems.pkauth.dropwizard.dagger.PkAuthModule;
import com.codeheadsystems.pkauth.dropwizard.json.PkAuthJacksonBridge;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.core.ConfiguredBundle;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import java.util.Objects;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dropwizard bundle that wires pk-auth's ceremony service, JWT issuance, and optional admin
 * endpoints into a host application. Brief §6.11.
 *
 * <p>Wiring is compile-time via Dagger 2 (ADR 0004). The host application supplies:
 *
 * <ol>
 *   <li>A {@code Configuration} class implementing {@link HasPkAuthConfig}.
 *   <li>A {@link PersistenceBindings} describing the SPI implementations (JDBI, DynamoDB, or the
 *       testkit's in-memory variant).
 *   <li>An optional {@link AdminService} — when present, the bundle registers {@link AdminResource}
 *       at {@code /auth/admin}.
 * </ol>
 *
 * <p><b>Jackson coexistence.</b> Dropwizard 5 still wires Jackson 2 internally; pk-auth-core uses
 * Jackson 3 (ADR 0009). The bundle teaches Dropwizard's Jackson 2 {@code ObjectMapper} how to read
 * and write base64url byte arrays and pk-auth's value types — see {@link PkAuthJacksonBridge}. Wire
 * compatibility is verified end-to-end by the integration tests.
 *
 * @param <C> the host application's Configuration type.
 */
public class PkAuthBundle<C extends HasPkAuthConfig> implements ConfiguredBundle<C> {

  private static final Logger LOG = LoggerFactory.getLogger(PkAuthBundle.class);

  private final PersistenceBindings persistence;
  private final @Nullable AdminService adminService;

  private @Nullable PkAuthComponent component;

  /**
   * Constructs a bundle without admin support. Only the four ceremony endpoints are mounted.
   *
   * @param persistence the SPI implementations used by the ceremony service.
   */
  public PkAuthBundle(PersistenceBindings persistence) {
    this(persistence, null);
  }

  /**
   * Constructs a bundle with optional admin support. When {@code adminService} is non-null the
   * bundle additionally registers {@link AdminResource}.
   *
   * @param persistence the SPI implementations used by the ceremony service.
   * @param adminService the admin service, or null to skip admin endpoint registration.
   */
  public PkAuthBundle(PersistenceBindings persistence, @Nullable AdminService adminService) {
    this.persistence = Objects.requireNonNull(persistence, "persistence");
    this.adminService = adminService;
  }

  @Override
  public void initialize(Bootstrap<?> bootstrap) {
    // Brief §6.11 — no additional bootstrap-phase wiring needed; Jersey resources are registered
    // in run(). We do register the Jackson 2 bridge here so any other bundle that reads the
    // ObjectMapper after us sees the pk-auth value-type serializers already installed.
    PkAuthJacksonBridge.register(bootstrap.getObjectMapper());
  }

  @Override
  public void run(C configuration, Environment environment) {
    this.component =
        DaggerPkAuthComponent.builder()
            .pkAuthModule(new PkAuthModule(configuration.pkAuth(), persistence))
            .build();

    // Ensure the runtime ObjectMapper has the bridge too (the environment may build its own copy
    // distinct from the bootstrap's).
    PkAuthJacksonBridge.register(environment.getObjectMapper());

    environment.jersey().register(component.ceremonyResource());
    environment
        .jersey()
        .register(
            new com.codeheadsystems.pkauth.dropwizard.resource.PkAuthPersistenceExceptionMapper());

    PasskeyAuthenticator authenticator = component.passkeyAuthenticator();
    environment.jersey().register(new AuthDynamicFeature(PasskeyAuthFilter.build(authenticator)));
    environment.jersey().register(new AuthValueFactoryProvider.Binder<>(PasskeyPrincipal.class));

    if (adminService != null) {
      environment.jersey().register(new AdminResource(adminService));
      LOG.info("pkauth.admin.endpoints.registered path=/auth/admin");
    }

    LOG.info(
        "pkauth.bundle.started rp={} issuer={}",
        configuration.pkAuth().relyingParty().id(),
        configuration.pkAuth().jwt().issuer());
  }

  /**
   * Returns the constructed Dagger component. Available after {@link #run} has executed; useful for
   * tests that want to peek at the JWT issuer / validator wired into the running app.
   */
  public PkAuthComponent component() {
    if (component == null) {
      throw new IllegalStateException("PkAuthBundle.run has not been invoked yet");
    }
    return component;
  }

  /** Convenience for tests / integrators that need the JWT issuer after the app has started. */
  public PkAuthJwtIssuer jwtIssuer() {
    return component().jwtIssuer();
  }

  /** Convenience for tests / integrators that need the JWT validator after the app has started. */
  public PkAuthJwtValidator jwtValidator() {
    return component().jwtValidator();
  }
}
