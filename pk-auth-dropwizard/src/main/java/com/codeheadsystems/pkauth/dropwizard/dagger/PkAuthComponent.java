// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard.dagger;

import com.codeheadsystems.pkauth.dropwizard.auth.PkAuthDropwizardAuthenticator;
import com.codeheadsystems.pkauth.dropwizard.resource.PkAuthCeremonyResource;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.lifecycle.UserDeletionService;
import com.codeheadsystems.pkauth.refresh.web.RefreshHandler;
import dagger.Component;
import jakarta.inject.Singleton;
import java.util.Optional;

/**
 * Dagger 2 component that materializes everything the bundle hands to Jersey. Brief §6.11 —
 * "@Component(modules = {...}) PkAuthComponent with provision methods for the Jersey resources".
 *
 * <p>The component intentionally only exposes the four ceremony pieces (resource + JWT
 * issuer/validator + authenticator). The admin graph lives in a separate optional component so
 * applications without {@code pk-auth-admin-api} on the classpath don't pay for it.
 */
@Singleton
@Component(modules = {PkAuthModule.class})
public interface PkAuthComponent {

  /** The ceremony resource Jersey mounts at {@code /auth}. */
  PkAuthCeremonyResource ceremonyResource();

  /** JWT validator used by the auth filter. */
  PkAuthJwtValidator jwtValidator();

  /** JWT issuer kept on the graph for resources / tests that want to mint tokens directly. */
  PkAuthJwtIssuer jwtIssuer();

  /** The authenticator the bundle plugs into Dropwizard's {@code AuthDynamicFeature}. */
  PkAuthDropwizardAuthenticator passkeyAuthenticator();

  /** User-deletion fan-out service. Always present; the listener set may be empty. */
  UserDeletionService userDeletionService();

  /**
   * Refresh handler; present only when {@code PersistenceBindings.refreshTokenRepository} is
   * non-null. The bundle uses presence to decide whether to mount {@code /auth/refresh}.
   *
   * @since 1.1.0
   */
  Optional<RefreshHandler> refreshHandler();
}
