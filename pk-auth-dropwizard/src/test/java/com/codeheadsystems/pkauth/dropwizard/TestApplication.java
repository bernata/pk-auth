// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.dropwizard;

import com.codeheadsystems.pkauth.admin.AdminAuthorizer;
import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.admin.DefaultAdminService;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.dropwizard.dagger.PersistenceBindings;
import com.codeheadsystems.pkauth.jwt.JwtConfig;
import com.codeheadsystems.pkauth.jwt.JwtKeyset;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.magiclink.LoggingEmailSender;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService;
import com.codeheadsystems.pkauth.otp.LoggingSmsSender;
import com.codeheadsystems.pkauth.otp.OtpService;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryBackupCodeRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryEverything;
import com.codeheadsystems.pkauth.testkit.InMemoryOtpRepository;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;

/**
 * Test-only Dropwizard application that boots the {@link PkAuthBundle} against the testkit's
 * in-memory SPIs and wires {@link DefaultAdminService} so the admin endpoints can be exercised.
 *
 * <p>State is exposed via a {@link ThreadLocal} so {@link DropwizardAppExtension} (which insists on
 * a {@code Class<? extends Application>}) can still hand the test a way in.
 */
public final class TestApplication extends Application<TestConfiguration> {

  /** Shared state between the test and the application instance Dropwizard constructs. */
  public static final class State {
    public final InMemoryEverything everything = InMemoryEverything.defaults();
    public final BackupCodeRepository backupCodes = new InMemoryBackupCodeRepository();
    public final OtpRepository otps = new InMemoryOtpRepository();
    public final ClockProvider clock = ClockProvider.system();
    public BackupCodeService backupCodeService;
    public MagicLinkService magicLinkService;
    public OtpService otpService;
    public AdminService adminService;
    public PkAuthBundle<TestConfiguration> bundle;
  }

  /** Active state seen by the next {@code new TestApplication()} invocation. */
  public static final ThreadLocal<State> ACTIVE = new ThreadLocal<>();

  private final State state;

  public TestApplication() {
    State current = ACTIVE.get();
    if (current == null) {
      current = new State();
      ACTIVE.set(current);
    }
    this.state = current;
  }

  public State state() {
    return state;
  }

  @Override
  public String getName() {
    return "pk-auth-dropwizard-test";
  }

  @Override
  public void initialize(Bootstrap<TestConfiguration> bootstrap) {
    state.backupCodeService = new BackupCodeService(state.backupCodes, state.clock);
    JwtKeyset keyset = JwtKeyset.hs256(new byte[32]);
    JwtConfig jwtConfig = JwtConfig.defaults("issuer-magic", "audience-magic");
    PkAuthJwtIssuer issuer = new PkAuthJwtIssuer(jwtConfig, keyset, state.clock);
    PkAuthJwtValidator validator = new PkAuthJwtValidator(jwtConfig, keyset, state.clock);
    state.magicLinkService =
        new MagicLinkService(
            issuer,
            validator,
            new LoggingEmailSender(),
            state.everything.users,
            state.clock,
            "https://example.com");
    state.otpService = new OtpService(state.otps, new LoggingSmsSender(), state.clock);
    state.adminService =
        DefaultAdminService.builder()
            .credentialRepository(state.everything.credentials)
            .userLookup(state.everything.users)
            .backupCodeService(state.backupCodeService)
            .magicLinkService(state.magicLinkService)
            .otpService(state.otpService)
            .authorizer(AdminAuthorizer.subjectScoped())
            .build();

    PersistenceBindings persistence =
        PersistenceBindings.builder()
            .credentialRepository(state.everything.credentials)
            .userLookup(state.everything.users)
            .challengeStore(state.everything.challenges)
            .backupCodeRepository(state.backupCodes)
            .otpRepository(state.otps)
            .build();
    state.bundle = new PkAuthBundle<>(persistence, state.adminService);
    bootstrap.addBundle(state.bundle);
  }

  @Override
  public void run(TestConfiguration configuration, Environment environment) {
    // Bundle does the work; tests poke at state directly.
  }
}
