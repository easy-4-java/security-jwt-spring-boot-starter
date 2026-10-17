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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

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
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        JwtAuthenticationProcessingFilter instance = new JwtAuthenticationProcessingFilter(null);
        assertThat(instance).isNotNull();
    }

    @Test
    void onlyPostRequestsToJwtLoginAreMatched() {
        TestFilter filter = new TestFilter();

        assertThat(filter.matches(request("POST", "/login/jwt"))).isTrue();
        assertThat(filter.matches(request("GET", "/login/jwt"))).isFalse();
        assertThat(filter.matches(request("POST", "/login"))).isFalse();
    }

    private static MockHttpServletRequest request(String method, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setServletPath(path);
        return request;
    }

    private static final class TestFilter extends JwtAuthenticationProcessingFilter {

        private TestFilter() {
            super(null);
        }

        private boolean matches(MockHttpServletRequest request) {
            return requiresAuthentication(request, new MockHttpServletResponse());
        }
    }
}
