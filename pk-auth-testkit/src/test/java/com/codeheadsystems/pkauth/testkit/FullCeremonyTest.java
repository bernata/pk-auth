// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * End-to-end acceptance test for Phase 3: drive a complete registration → assertion ceremony
 * through {@code DefaultPasskeyAuthenticationService} using {@link FakeAuthenticator}.
 */
class FullCeremonyTest {

  @Test
  void registrationThenAssertionSucceedsAndBumpsSignCount() {
    InMemoryEverything env = InMemoryEverything.defaults();

    // Register a new user + credential.
    StartRegistrationResponse start =
        env.service.startRegistration(new StartRegistrationRequest("alice", "Alice", null, null));
    UserHandle handle = env.users.findUserHandleByUsername("alice").orElseThrow();

    RegistrationResponseJson regResp = env.authenticator.createRegistrationResponse(start);
    RegistrationResult regResult =
        env.service.finishRegistration(
            new FinishRegistrationRequest(start.challengeId(), "alice", "Test key", regResp));

    assertThat(regResult).isInstanceOf(RegistrationResult.Success.class);
    RegistrationResult.Success success = (RegistrationResult.Success) regResult;
    assertThat(success.credential().userHandle()).isEqualTo(handle);
    assertThat(success.credential().label()).isEqualTo("Test key");

    Optional<CredentialRecord> stored =
        env.credentials.findByCredentialId(success.credential().credentialId());
    assertThat(stored).isPresent();
    assertThat(stored.get().signCount()).isZero();

    // Authenticate twice in a row; sign counter should increment each time.
    AssertionResult firstAssert = assertOnce(env, handle);
    assertThat(firstAssert)
        .isInstanceOfSatisfying(
            AssertionResult.Success.class, s -> assertThat(s.signCount()).isEqualTo(1L));

    AssertionResult secondAssert = assertOnce(env, handle);
    assertThat(secondAssert)
        .isInstanceOfSatisfying(
            AssertionResult.Success.class, s -> assertThat(s.signCount()).isEqualTo(2L));

    assertThat(
            env.credentials
                .findByCredentialId(success.credential().credentialId())
                .orElseThrow()
                .signCount())
        .isEqualTo(2L);
    assertThat(env.challenges.size()).isZero(); // ChallengeStore consumes single-use challenges.
  }

  @Test
  void usernamelessFlowSucceedsWhenSingleCredentialRegistered() {
    InMemoryEverything env = InMemoryEverything.defaults();
    UserHandle handle = register(env);

    StartAuthenticationResponse start =
        env.service.startAuthentication(new StartAuthenticationRequest(null, null));
    assertThat(start.publicKey().allowCredentials()).isNull();

    AuthenticationResponseJson resp = env.authenticator.createAssertionResponse(start, handle);
    AssertionResult result =
        env.service.finishAuthentication(
            new FinishAuthenticationRequest(start.challengeId(), resp));
    assertThat(result).isInstanceOf(AssertionResult.Success.class);
  }

  @Test
  void duplicateRegistrationIsRejectedOnSecondAttempt() {
    InMemoryEverything env = InMemoryEverything.defaults();
    register(env);

    // Mint a second authenticator that reuses the same credential ID — easiest way is to
    // re-register against the same env, but with a fresh authenticator instance whose
    // credential IDs would normally be unique. Instead, replay the stored credential's id by
    // saving it twice via the in-memory repo directly; this proves the repository's duplicate
    // guard catches it.
    CredentialRecord existing =
        env.credentials
            .findByUserHandle(env.users.findUserHandleByUsername("alice").orElseThrow())
            .get(0);
    try {
      env.credentials.save(existing);
      throw new AssertionError("expected duplicate save to throw");
    } catch (IllegalStateException expected) {
      assertThat(expected).hasMessageContaining("Duplicate");
    }
  }

  // -- helpers --

  private static UserHandle register(InMemoryEverything env) {
    StartRegistrationResponse start =
        env.service.startRegistration(new StartRegistrationRequest("alice", "Alice", null, null));
    RegistrationResponseJson resp = env.authenticator.createRegistrationResponse(start);
    RegistrationResult result =
        env.service.finishRegistration(
            new FinishRegistrationRequest(start.challengeId(), "alice", "Test key", resp));
    assertThat(result).isInstanceOf(RegistrationResult.Success.class);
    return ((RegistrationResult.Success) result).credential().userHandle();
  }

  private static AssertionResult assertOnce(InMemoryEverything env, UserHandle handle) {
    StartAuthenticationResponse start =
        env.service.startAuthentication(new StartAuthenticationRequest("alice", null));
    AuthenticationResponseJson resp = env.authenticator.createAssertionResponse(start, handle);
    return env.service.finishAuthentication(
        new FinishAuthenticationRequest(start.challengeId(), resp));
  }
}
