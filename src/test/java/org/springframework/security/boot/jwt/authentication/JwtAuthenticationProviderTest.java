/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
package org.springframework.security.boot.jwt.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("JwtAuthenticationProvider Tests")
class JwtAuthenticationProviderTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(null, null);
        assertThat(provider).isNotNull();
    }

    @Test
    @DisplayName("supports JwtAuthenticationToken")
    void testSupports() {
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(null, null);
        assertThat(provider.supports(JwtAuthenticationToken.class)).isTrue();
        assertThat(provider.supports(org.springframework.security.authentication.UsernamePasswordAuthenticationToken.class)).isFalse();
    }

    @Test
    @DisplayName("getUserDetailsChecker returns default checker")
    void testGetUserDetailsChecker() {
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(null, null);
        UserDetailsChecker checker = provider.getUserDetailsChecker();
        assertThat(checker).isNotNull();
        assertThat(checker).isInstanceOf(AccountStatusUserDetailsChecker.class);
    }

    @Test
    @DisplayName("setUserDetailsChecker stores checker")
    void testSetUserDetailsChecker() {
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(null, null);
        UserDetailsChecker customChecker = new AccountStatusUserDetailsChecker();
        provider.setUserDetailsChecker(customChecker);
        assertThat(provider.getUserDetailsChecker()).isSameAs(customChecker);
    }

    @Test
    @DisplayName("getPasswordEncoder returns encoder from constructor")
    void testGetPasswordEncoder() {
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(null, encoder);
        assertThat(provider.getPasswordEncoder()).isSameAs(encoder);
    }

    @Test
    @DisplayName("getUserDetailsService returns service from constructor")
    void testGetUserDetailsService() {
        UserDetailsServiceAdapter service = mock(UserDetailsServiceAdapter.class);
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(service, null);
        assertThat(provider.getUserDetailsService()).isSameAs(service);
    }

    @Test
    @DisplayName("authenticate throws BadCredentialsException when username is blank")
    void testAuthenticateBlankUsername() {
        UserDetailsServiceAdapter service = mock(UserDetailsServiceAdapter.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(service, encoder);

        JwtAuthenticationToken token = new JwtAuthenticationToken("", "password");
        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    @DisplayName("authenticate throws BadCredentialsException when password is blank")
    void testAuthenticateBlankPassword() {
        UserDetailsServiceAdapter service = mock(UserDetailsServiceAdapter.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(service, encoder);

        JwtAuthenticationToken token = new JwtAuthenticationToken("user", "");
        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    @DisplayName("authenticate throws BadCredentialsException when password does not match")
    void testAuthenticatePasswordMismatch() {
        UserDetailsServiceAdapter service = mock(UserDetailsServiceAdapter.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        UserDetails userDetails = new User("user", "encodedPass",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        when(service.loadUserDetails(any(Authentication.class))).thenReturn(userDetails);
        when(encoder.matches(any(), any())).thenReturn(false);

        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(service, encoder);
        JwtAuthenticationToken token = new JwtAuthenticationToken("user", "wrongPassword");

        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    @DisplayName("authenticate succeeds with valid credentials and regular UserDetails")
    void testAuthenticateSuccess() {
        UserDetailsServiceAdapter service = mock(UserDetailsServiceAdapter.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        UserDetails userDetails = new User("user", "encodedPass",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        when(service.loadUserDetails(any(Authentication.class))).thenReturn(userDetails);
        when(encoder.matches(any(), any())).thenReturn(true);

        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(service, encoder);
        JwtAuthenticationToken token = new JwtAuthenticationToken("user", "correctPassword");

        JwtAuthenticationToken result = (JwtAuthenticationToken) provider.authenticate(token);
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal()).isEqualTo("user");
    }

    @Test
    @DisplayName("authenticate succeeds with SecurityPrincipal")
    void testAuthenticateSuccessWithSecurityPrincipal() {
        UserDetailsServiceAdapter service = mock(UserDetailsServiceAdapter.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        org.springframework.security.boot.biz.userdetails.SecurityPrincipal principal =
                new org.springframework.security.boot.biz.userdetails.SecurityPrincipal(
                        "uid-1", "tid-1", true, true, true, true,
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        when(service.loadUserDetails(any(Authentication.class))).thenReturn(principal);
        when(encoder.matches(any(), any())).thenReturn(true);

        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(service, encoder);
        JwtAuthenticationToken token = new JwtAuthenticationToken("user", "correctPassword");
        token.setSign("sig");
        token.setLongitude(120.0);
        token.setLatitude(30.0);

        JwtAuthenticationToken result = (JwtAuthenticationToken) provider.authenticate(token);
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
    }
}
