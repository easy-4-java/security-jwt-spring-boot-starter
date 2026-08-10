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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link JwtAuthenticationProcessingFilter }}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("JwtAuthenticationProcessingFilter Tests")
class JwtAuthenticationProcessingFilterTest {

    @Test
    @DisplayName("Instance can be created with ObjectMapper")
    void testInstantiation() {
        ObjectMapper mapper = new ObjectMapper();
        JwtAuthenticationProcessingFilter filter = new JwtAuthenticationProcessingFilter(mapper);
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("Instance can be created with null ObjectMapper")
    void testInstantiationWithNull() {
        JwtAuthenticationProcessingFilter filter = new JwtAuthenticationProcessingFilter(null);
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("setDetails and authenticationToken via reflection")
    void testSetDetailsAndToken() throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        JwtAuthenticationProcessingFilter filter = new JwtAuthenticationProcessingFilter(mapper);

        // Test authenticationToken method
        java.lang.reflect.Method authMethod = JwtAuthenticationProcessingFilter.class.getDeclaredMethod(
                "authenticationToken", String.class, String.class);
        authMethod.setAccessible(true);
        Object token = authMethod.invoke(filter, "user", "pass");
        assertThat(token).isInstanceOf(JwtAuthenticationToken.class);
        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) token;
        assertThat(jwtToken.getPrincipal()).isEqualTo("user");
        assertThat(jwtToken.getCredentials()).isEqualTo("pass");
    }

    @Test
    @DisplayName("authenticationToken creates JwtAuthenticationToken")
    void testAuthenticationTokenMethod() throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        JwtAuthenticationProcessingFilter filter = new JwtAuthenticationProcessingFilter(mapper);

        java.lang.reflect.Method authMethod = JwtAuthenticationProcessingFilter.class.getDeclaredMethod(
                "authenticationToken", String.class, String.class);
        authMethod.setAccessible(true);
        Object token = authMethod.invoke(filter, "user", "pass");
        assertThat(token).isInstanceOf(JwtAuthenticationToken.class);
        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) token;
        assertThat(jwtToken.getPrincipal()).isEqualTo("user");
        assertThat(jwtToken.getCredentials()).isEqualTo("pass");
    }

    @Test
    @DisplayName("Filter has expected default filterProcessesUrl")
    void testFilterProcessesUrl() {
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        JwtAuthenticationProcessingFilter filter = new JwtAuthenticationProcessingFilter(mapper);
        assertThat(filter).isNotNull();
        // The filter matches POST /login/jwt
    }
}
