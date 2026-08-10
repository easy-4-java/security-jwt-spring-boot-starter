/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
package org.springframework.security.boot.jwt.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("JwtAuthorizationToken Tests")
class JwtAuthorizationTokenTest {

    @Test
    @DisplayName("Unauthenticated constructor stores principal and credentials")
    void testUnauthenticatedConstructor() {
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid", "jwt-token");
        assertThat(token.getPrincipal()).isEqualTo("uid");
        assertThat(token.getCredentials()).isEqualTo("jwt-token");
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    @DisplayName("Authenticated constructor stores authorities")
    void testAuthenticatedConstructor() {
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid", "jwt-token",
                Collections.singletonList(authority));
        assertThat(token.isAuthenticated()).isTrue();
        assertThat(token.getAuthorities()).containsExactly(authority);
    }

    @Test
    @DisplayName("setAuthenticated(true) throws IllegalArgumentException")
    void testSetAuthenticatedTrueThrows() {
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid", "jwt-token");
        assertThatThrownBy(() -> token.setAuthenticated(true))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("setAuthenticated(false) works")
    void testSetAuthenticatedFalse() {
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid", "jwt-token");
        token.setAuthenticated(false);
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    @DisplayName("eraseCredentials nulls credentials")
    void testEraseCredentials() {
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid", "jwt-token");
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();
    }

    @Test
    @DisplayName("Sign, longitude and latitude getters/setters round-trip")
    void testGeoFields() {
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid", "jwt-token");
        token.setSign("sig");
        token.setLongitude(120.0);
        token.setLatitude(30.0);
        assertThat(token.getSign()).isEqualTo("sig");
        assertThat(token.getLongitude()).isEqualTo(120.0);
        assertThat(token.getLatitude()).isEqualTo(30.0);
    }
}
