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
package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.boot.jwt.authentication.server.JwtMatchedServerAuthenticationEntryPoint;
import org.springframework.security.boot.jwt.authentication.server.JwtMatchedServerAuthenticationFailureHandler;
import org.springframework.security.boot.jwt.authentication.server.JwtMatchedServerAuthenticationSuccessHandler;
import org.springframework.security.boot.jwt.authentication.server.JwtServerAuthenticationConverter;
import org.springframework.security.boot.jwt.authentication.server.JwtServerAuthorizationSecurityContextRepository;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {{ @link ReactiveSecurityJwtAutoConfiguration }}.
 *
 * <p>Verifies the auto-configuration class can be instantiated and
 * its factory methods produce the expected beans.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("ReactiveSecurityJwtAutoConfiguration Tests")
class ReactiveSecurityJwtAutoConfigurationTest {

    private final ReactiveSecurityJwtAutoConfiguration configuration = new ReactiveSecurityJwtAutoConfiguration();

    @Test
    @DisplayName("Auto-configuration class can be instantiated")
    void testInstantiation() {
        assertThat(configuration).isNotNull();
    }

    @Test
    @DisplayName("jwtMatchedServerAuthenticationEntryPoint returns non-null entry point")
    void testJwtMatchedServerAuthenticationEntryPoint() {
        JwtMatchedServerAuthenticationEntryPoint entryPoint = configuration.jwtMatchedServerAuthenticationEntryPoint();
        assertThat(entryPoint).isNotNull();
    }

    @Test
    @DisplayName("jwtMatchedServerAuthenticationFailureHandler returns non-null failure handler")
    void testJwtMatchedServerAuthenticationFailureHandler() {
        JwtMatchedServerAuthenticationFailureHandler handler = configuration.jwtMatchedServerAuthenticationFailureHandler();
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("jwtMatchedServerAuthenticationSuccessHandler returns non-null success handler")
    void testJwtMatchedServerAuthenticationSuccessHandler() {
        JwtPayloadRepository payloadRepository = mock(JwtPayloadRepository.class);
        JwtMatchedServerAuthenticationSuccessHandler handler = configuration.jwtMatchedServerAuthenticationSuccessHandler(payloadRepository);
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("payloadRepository returns non-null repository")
    void testPayloadRepository() {
        JwtPayloadRepository repository = configuration.payloadRepository();
        assertThat(repository).isNotNull();
    }

    @Test
    @DisplayName("jwtReactiveAuthenticationManager returns non-null manager")
    void testJwtReactiveAuthenticationManager() {
        JwtPayloadRepository payloadRepository = mock(JwtPayloadRepository.class);
        SecurityJwtAuthzProperties authzProperties = new SecurityJwtAuthzProperties();
        ReactiveAuthenticationManager manager = configuration.jwtReactiveAuthenticationManager(payloadRepository, authzProperties);
        assertThat(manager).isNotNull();
    }

    @Test
    @DisplayName("jwtServerAuthenticationConverter returns non-null converter")
    void testJwtServerAuthenticationConverter() {
        ServerAuthenticationConverter converter = configuration.jwtServerAuthenticationConverter();
        assertThat(converter).isNotNull();
    }

    @Test
    @DisplayName("jwtServerSecurityContextRepository returns non-null repository")
    void testJwtServerSecurityContextRepository() {
        JwtPayloadRepository payloadRepository = mock(JwtPayloadRepository.class);
        SecurityJwtAuthzProperties authzProperties = new SecurityJwtAuthzProperties();
        ReactiveAuthenticationManager authManager = configuration.jwtReactiveAuthenticationManager(payloadRepository, authzProperties);
        ServerSecurityContextRepository repository = configuration.jwtServerSecurityContextRepository(authManager);
        assertThat(repository).isNotNull();
    }
}
