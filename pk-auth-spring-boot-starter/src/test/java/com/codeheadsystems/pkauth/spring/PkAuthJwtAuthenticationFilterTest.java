// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.spring.security.PkAuthJwtAuthenticationFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Regression test for item #41 in TODO.md: the filter must authenticate only on the {@code
 * Authorization: Bearer …} header. A request that carries cookies (e.g. {@code JSESSIONID}) but no
 * {@code Authorization} header must not be authenticated, since the pk-auth filter chain disables
 * CSRF on the assumption that auth never depends on a cookie.
 */
class PkAuthJwtAuthenticationFilterTest {

  private PkAuthJwtValidator validator;
  private PkAuthJwtAuthenticationFilter filter;

  @BeforeEach
  void setUp() {
    validator = mock(PkAuthJwtValidator.class);
    filter = new PkAuthJwtAuthenticationFilter(validator);
    SecurityContextHolder.clearContext();
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void cookieOnlyRequestDoesNotAuthenticate() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/auth/whoami");
    request.setCookies(new Cookie("JSESSIONID", "session-value"));
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(request, response, chain);

    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(validator, never()).validate(anyString());
    verify(chain).doFilter(request, response);
  }

  @Test
  void missingHeaderDoesNotAuthenticate() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/auth/whoami");
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(request, response, chain);

    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(validator, never()).validate(anyString());
  }

  @Test
  void nonBearerHeaderDoesNotAuthenticate() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/auth/whoami");
    request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(request, response, chain);

    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(validator, never()).validate(anyString());
  }

  @Test
  void emptyBearerDoesNotInvokeValidator() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/auth/whoami");
    request.addHeader("Authorization", "Bearer  ");
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);
    when(validator.validate(anyString())).thenThrow(new AssertionError("validator should not run"));

    filter.doFilter(request, response, chain);

    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }
}
