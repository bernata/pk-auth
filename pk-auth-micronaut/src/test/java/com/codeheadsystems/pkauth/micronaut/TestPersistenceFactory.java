// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.testkit.InMemoryBackupCodeRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryChallengeStore;
import com.codeheadsystems.pkauth.testkit.InMemoryCredentialRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryOtpRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryRefreshTokenRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryUserLookup;
import io.micronaut.context.annotation.Factory;
import jakarta.inject.Singleton;

/** Test-only factory wiring the in-memory SPIs. */
@Factory
public class TestPersistenceFactory {

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

  @Singleton
  RefreshTokenRepository refreshTokenRepository() {
    return new InMemoryRefreshTokenRepository();
  }
}
