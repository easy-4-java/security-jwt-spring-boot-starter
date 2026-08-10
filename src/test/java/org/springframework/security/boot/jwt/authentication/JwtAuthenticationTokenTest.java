/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.jwt.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {{ @link JwtAuthenticationToken }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("JwtAuthenticationToken Tests")
class JwtAuthenticationTokenTest {

    @Test
    @DisplayName("Unauthenticated token stores principal and credentials")
    void testUnauthenticatedConstructor() {
        JwtAuthenticationToken token = new JwtAuthenticationToken("user", "pass");
        assertThat(token).isNotNull();
        assertThat(token.getPrincipal()).isEqualTo("user");
        assertThat(token.getCredentials()).isEqualTo("pass");
        assertThat(token.isAuthenticated()).isFalse();
        assertThat(token.getAuthorities()).isEmpty();
    }

    @Test
    @DisplayName("Authenticated token stores principal, credentials and authorities")
    void testAuthenticatedConstructor() {
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_ADMIN");
        JwtAuthenticationToken token = new JwtAuthenticationToken("user", "pass",
                Collections.singletonList(authority));
        assertThat(token.getPrincipal()).isEqualTo("user");
        assertThat(token.getCredentials()).isEqualTo("pass");
        assertThat(token.isAuthenticated()).isTrue();
        assertThat(token.getAuthorities()).containsExactly(authority);
    }

    @Test
    @DisplayName("setAuthenticated(true) throws IllegalArgumentException")
    void testSetAuthenticatedTrueThrows() {
        JwtAuthenticationToken token = new JwtAuthenticationToken("user", "pass");
        assertThatThrownBy(() -> token.setAuthenticated(true))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("setAuthenticated(false) works")
    void testSetAuthenticatedFalse() {
        JwtAuthenticationToken token = new JwtAuthenticationToken("user", "pass");
        token.setAuthenticated(false);
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    @DisplayName("eraseCredentials nulls credentials but keeps principal")
    void testEraseCredentials() {
        JwtAuthenticationToken token = new JwtAuthenticationToken("user", "pass");
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();
        assertThat(token.getPrincipal()).isEqualTo("user");
    }

    @Test
    @DisplayName("Sign, longitude and latitude getters/setters round-trip")
    void testGeoFields() {
        JwtAuthenticationToken token = new JwtAuthenticationToken("user", "pass");
        token.setSign("abc123");
        token.setLongitude(116.4);
        token.setLatitude(39.9);
        assertThat(token.getSign()).isEqualTo("abc123");
        assertThat(token.getLongitude()).isEqualTo(116.4);
        assertThat(token.getLatitude()).isEqualTo(39.9);
    }
}
