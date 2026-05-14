// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.examples.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Lights up the demo Spring Boot application and exercises three things:
 *
 * <ul>
 *   <li>the application context refreshes cleanly,
 *   <li>the SPA index page is served at {@code /},
 *   <li>the starter's ceremony endpoint is reachable (the demo doesn't redefine it — this proves
 *       the starter wiring is present in the demo's classpath).
 * </ul>
 *
 * <p>Full ceremony coverage lives in {@code pk-auth-spring-boot-starter}'s integration tests.
 */
@SpringBootTest(classes = SpringBootDemoApplication.class)
@AutoConfigureMockMvc
class SpringBootDemoApplicationTest {

  @Autowired private MockMvc mockMvc;

  @Test
  void contextLoads() {
    assertThat(mockMvc).isNotNull();
  }

  @Test
  void indexPageServesHtml() throws Exception {
    mockMvc
        .perform(get("/"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
        .andExpect(
            content().string(org.hamcrest.Matchers.containsString("pk-auth Spring Boot demo")));
  }

  @Test
  void ceremonyStartEndpointIsMounted() throws Exception {
    mockMvc
        .perform(
            post("/auth/passkeys/registration/start")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"demo-user\"}"))
        .andExpect(status().isOk());
  }
}
