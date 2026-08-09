/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
package org.springframework.security.boot.jwt.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.exception.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("JWT Handlers Tests")
class JwtHandlersTest {

    // ---- JwtMatchedAuthenticationEntryPoint ----

    @Test
    @DisplayName("JwtMatchedAuthenticationEntryPoint supports all JWT exceptions")
    void testEntryPointSupports() {
        JwtMatchedAuthenticationEntryPoint entryPoint = new JwtMatchedAuthenticationEntryPoint();
        assertThat(entryPoint.supports(new AuthenticationJwtExpiredException("expired"))).isTrue();
        assertThat(entryPoint.supports(new AuthenticationJwtNotFoundException("not found"))).isTrue();
        assertThat(entryPoint.supports(new AuthenticationJwtInvalidException("invalid"))).isTrue();
        assertThat(entryPoint.supports(new AuthenticationJwtIncorrectException("incorrect"))).isTrue();
        assertThat(entryPoint.supports(new AuthenticationJwtIssuedException("issued"))).isTrue();
    }

    @Test
    @DisplayName("JwtMatchedAuthenticationEntryPoint does not support generic exceptions")
    void testEntryPointDoesNotSupportGeneric() {
        JwtMatchedAuthenticationEntryPoint entryPoint = new JwtMatchedAuthenticationEntryPoint();
        assertThat(entryPoint.supports(new BadCredentialsException("bad"))).isFalse();
    }

    // ---- JwtMatchedAuthenticationSuccessHandler ----

    @Test
    @DisplayName("JwtMatchedAuthenticationSuccessHandler can be instantiated")
    void testSuccessHandlerInstantiation() {
        JwtPayloadRepository repo = new JwtPayloadRepository() {};
        JwtMatchedAuthenticationSuccessHandler handler = new JwtMatchedAuthenticationSuccessHandler(repo);
        assertThat(handler).isNotNull();
        assertThat(handler.getPayloadRepository()).isSameAs(repo);
    }

    @Test
    @DisplayName("JwtMatchedAuthenticationSuccessHandler supports JwtAuthenticationToken")
    void testSuccessHandlerSupportsJwtToken() {
        JwtPayloadRepository repo = new JwtPayloadRepository() {};
        JwtMatchedAuthenticationSuccessHandler handler = new JwtMatchedAuthenticationSuccessHandler(repo);
        JwtAuthenticationToken jwtToken = new JwtAuthenticationToken("user", "pass");
        assertThat(handler.supports(jwtToken)).isTrue();
    }

    @Test
    @DisplayName("JwtMatchedAuthenticationSuccessHandler does not support generic auth")
    void testSuccessHandlerSupportsGeneric() {
        JwtPayloadRepository repo = new JwtPayloadRepository() {};
        JwtMatchedAuthenticationSuccessHandler handler = new JwtMatchedAuthenticationSuccessHandler(repo);
        Authentication auth = mock(Authentication.class);
        assertThat(handler.supports(auth)).isFalse();
    }

    @Test
    @DisplayName("JwtMatchedAuthenticationSuccessHandler checkExpiry getter/setter")
    void testSuccessHandlerCheckExpiry() {
        JwtPayloadRepository repo = new JwtPayloadRepository() {};
        JwtMatchedAuthenticationSuccessHandler handler = new JwtMatchedAuthenticationSuccessHandler(repo);
        handler.setCheckExpiry(true);
        assertThat(handler.isCheckExpiry()).isTrue();
    }

    // ---- JwtMatchedAuthcOrAuthzFailureHandler ----

    @Test
    @DisplayName("JwtMatchedAuthcOrAuthzFailureHandler can be instantiated")
    void testFailureHandlerInstantiation() {
        JwtMatchedAuthcOrAuthzFailureHandler handler = new JwtMatchedAuthcOrAuthzFailureHandler();
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("JwtMatchedAuthcOrAuthzFailureHandler supports all JWT exceptions")
    void testFailureHandlerSupports() {
        JwtMatchedAuthcOrAuthzFailureHandler handler = new JwtMatchedAuthcOrAuthzFailureHandler();
        assertThat(handler.supports(new AuthenticationJwtExpiredException("expired"))).isTrue();
        assertThat(handler.supports(new AuthenticationJwtNotFoundException("not found"))).isTrue();
        assertThat(handler.supports(new AuthenticationJwtInvalidException("invalid"))).isTrue();
        assertThat(handler.supports(new AuthenticationJwtIncorrectException("incorrect"))).isTrue();
        assertThat(handler.supports(new AuthenticationJwtIssuedException("issued"))).isTrue();
        assertThat(handler.supports(new BadCredentialsException("bad"))).isFalse();
    }

    // ---- JwtAuthorizationSuccessHandler ----

    @Test
    @DisplayName("JwtAuthorizationSuccessHandler can be instantiated")
    void testAuthzSuccessHandlerInstantiation() {
        JwtAuthorizationSuccessHandler handler = new JwtAuthorizationSuccessHandler();
        assertThat(handler).isNotNull();
    }

    // ---- JwtAuthorizationProcessingFilter with ignore patterns ----

    @Test
    @DisplayName("JwtAuthorizationProcessingFilter setIgnoreRequestMatcher with null list")
    void testSetIgnoreRequestMatcherNull() {
        JwtAuthorizationProcessingFilter filter = new JwtAuthorizationProcessingFilter();
        filter.setIgnoreRequestMatcher(null);
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("JwtAuthorizationProcessingFilter doFilter with non-matching request")
    void testDoFilterNonMatching() throws Exception {
        JwtAuthorizationProcessingFilter filter = new JwtAuthorizationProcessingFilter();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/public/resource");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (req, res) -> {});
    }

    // ---- JwtAuthorizationSuccessHandler ----

    @Test
    @DisplayName("JwtAuthorizationSuccessHandler onAuthenticationSuccess with no session")
    void testAuthzSuccessHandlerNoSession() throws Exception {
        JwtAuthorizationSuccessHandler handler = new JwtAuthorizationSuccessHandler();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        org.springframework.security.core.Authentication auth = mock(org.springframework.security.core.Authentication.class);
        handler.onAuthenticationSuccess(request, response, auth);
    }

    @Test
    @DisplayName("JwtAuthorizationSuccessHandler onAuthenticationSuccess with session")
    void testAuthzSuccessHandlerWithSession() throws Exception {
        JwtAuthorizationSuccessHandler handler = new JwtAuthorizationSuccessHandler();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true); // create session
        MockHttpServletResponse response = new MockHttpServletResponse();
        org.springframework.security.core.Authentication auth = mock(org.springframework.security.core.Authentication.class);
        handler.onAuthenticationSuccess(request, response, auth);
    }

    // ---- JwtMatchedAuthenticationSuccessHandler onAuthenticationSuccess ----

    @Test
    @DisplayName("JwtMatchedAuthenticationSuccessHandler onAuthenticationSuccess")
    void testSuccessHandlerOnSuccess() throws Exception {
        JwtPayloadRepository repo = mock(JwtPayloadRepository.class);
        org.mockito.Mockito.when(repo.getProfilePayload(
                org.mockito.ArgumentMatchers.any(org.springframework.security.authentication.AbstractAuthenticationToken.class),
                org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(new org.springframework.security.boot.biz.userdetails.UserProfilePayload());
        JwtMatchedAuthenticationSuccessHandler handler = new JwtMatchedAuthenticationSuccessHandler(repo);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        JwtAuthenticationToken auth = new JwtAuthenticationToken("user", "pass",
                java.util.Collections.singletonList(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")));
        handler.onAuthenticationSuccess(request, response, auth);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    // ---- JwtMatchedAuthcOrAuthzFailureHandler onAuthenticationFailure ----

    @Test
    @DisplayName("JwtMatchedAuthcOrAuthzFailureHandler onAuthenticationFailure")
    void testFailureHandlerOnFailure() throws Exception {
        JwtMatchedAuthcOrAuthzFailureHandler handler = new JwtMatchedAuthcOrAuthzFailureHandler();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new AuthenticationJwtNotFoundException("not found"));
        assertThat(response.getStatus()).isEqualTo(200); // writes JSON response
    }

    // ---- JwtMatchedAuthenticationEntryPoint commence ----

    @Test
    @DisplayName("JwtMatchedAuthenticationEntryPoint commence")
    void testEntryPointCommence() throws Exception {
        JwtMatchedAuthenticationEntryPoint entryPoint = new JwtMatchedAuthenticationEntryPoint();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        org.springframework.security.core.Authentication auth = mock(org.springframework.security.core.Authentication.class);
        entryPoint.commence(request, response, new AuthenticationJwtNotFoundException("not found"));
        assertThat(response.getStatus()).isEqualTo(200); // writes JSON response
    }
}
