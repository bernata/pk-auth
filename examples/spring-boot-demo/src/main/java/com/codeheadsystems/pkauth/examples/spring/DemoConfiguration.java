// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.examples.spring;

import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Demo-specific overrides. We set the relying-party config from a {@code demo.*} property block so
 * a reviewer can change the origin without touching the starter's {@code pkauth.relying-party.*}
 * properties (which the starter binds as a record and would re-introduce the chicken-and-egg of the
 * demo importing the starter's property class).
 */
@Configuration
@EnableConfigurationProperties(DemoConfiguration.DemoProperties.class)
public class DemoConfiguration {

  @Bean
  @Primary
  public RelyingPartyConfig demoRelyingPartyConfig(DemoProperties props) {
    return new RelyingPartyConfig(props.rpId(), props.rpName(), Set.copyOf(props.origins()));
  }

  /** Demo's own property bundle. */
  @ConfigurationProperties("demo")
  public record DemoProperties(
      String rpId, String rpName, java.util.List<String> origins, String persistence) {
    public DemoProperties {
      if (rpId == null) {
        rpId = "localhost";
      }
      if (rpName == null) {
        rpName = "pk-auth Spring Boot demo";
      }
      if (origins == null || origins.isEmpty()) {
        origins = java.util.List.of("http://localhost:8080");
      }
      if (persistence == null) {
        persistence = "memory";
      }
    }
  }
}
