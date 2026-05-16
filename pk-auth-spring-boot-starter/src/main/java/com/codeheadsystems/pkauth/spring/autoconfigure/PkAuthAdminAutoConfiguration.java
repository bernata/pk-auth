// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring.autoconfigure;

import com.codeheadsystems.pkauth.admin.AdminAuthorizer;
import com.codeheadsystems.pkauth.admin.AdminService;
import com.codeheadsystems.pkauth.admin.DefaultAdminService;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.magiclink.MagicLinkService;
import com.codeheadsystems.pkauth.otp.OtpService;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.spring.admin.PkAuthAdminController;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Wires the admin service + controller iff {@code pk-auth-admin-api} is on the classpath (brief
 * §6.10: "If {@code pk-auth-admin-api} is on the classpath … also wires {@code
 * PkAuthAdminController}").
 *
 * <p>The {@link ConditionalOnClass} guard uses the class-name string form so this autoconfig can be
 * loaded without {@code pk-auth-admin-api} present without triggering {@code NoClassDefFoundError}
 * on the {@code @Bean} return types — Spring resolves the class names lazily.
 */
@AutoConfiguration(after = PkAuthAutoConfiguration.class)
@ConditionalOnClass(name = "com.codeheadsystems.pkauth.admin.AdminService")
public class PkAuthAdminAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public AdminAuthorizer pkAuthAdminAuthorizer() {
    return AdminAuthorizer.subjectScoped();
  }

  @Bean
  @ConditionalOnMissingBean
  public AdminService pkAuthAdminService(
      CredentialRepository credentialRepository,
      UserLookup userLookup,
      BackupCodeService backupCodeService,
      MagicLinkService magicLinkService,
      OtpService otpService,
      AdminAuthorizer authorizer) {
    return DefaultAdminService.builder()
        .credentialRepository(credentialRepository)
        .userLookup(userLookup)
        .backupCodeService(backupCodeService)
        .magicLinkService(magicLinkService)
        .otpService(otpService)
        .authorizer(authorizer)
        .build();
  }

  @Bean
  @ConditionalOnMissingBean
  public PkAuthAdminController pkAuthAdminController(AdminService adminService) {
    return new PkAuthAdminController(adminService);
  }
}
