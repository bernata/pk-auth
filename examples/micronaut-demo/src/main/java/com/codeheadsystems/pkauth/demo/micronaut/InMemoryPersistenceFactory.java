// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.demo.micronaut;

import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.testkit.InMemoryBackupCodeRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryChallengeStore;
import com.codeheadsystems.pkauth.testkit.InMemoryCredentialRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryOtpRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryUserLookup;
import io.micronaut.context.annotation.Factory;
import jakarta.inject.Singleton;

/**
 * Wires the testkit's in-memory SPIs as Micronaut beans for the demo. Production deployments swap
 * these out by providing competing beans (e.g., from {@code pk-auth-persistence-jdbi}).
 */
@Factory
public class InMemoryPersistenceFactory {

  @Singleton
  CredentialRepository credentialRepository() {
    return new InMemoryCredentialRepository();
  }

  @Singleton
  UserLookup userLookup() {
    return new InMemoryUserLookup();
  }

  @Singleton
  ChallengeStore challengeStore() {
    return new InMemoryChallengeStore();
  }

  @Singleton
  BackupCodeRepository backupCodeRepository() {
    return new InMemoryBackupCodeRepository();
  }

  @Singleton
  OtpRepository otpRepository() {
    return new InMemoryOtpRepository();
  }
}
