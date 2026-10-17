package org.springframework.security.boot.jwt.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class JwtAuthorizationProcessingFilterTest {

    @Test
    void ignoredPathsBypassAuthorization() {
        TestFilter filter = new TestFilter(List.of("/public/**"));

        assertThat(filter.matches(request("/public/status"))).isFalse();
        assertThat(filter.matches(request("/api/orders"))).isTrue();
    }

    private static MockHttpServletRequest request(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setServletPath(path);
        return request;
    }

    private static final class TestFilter extends JwtAuthorizationProcessingFilter {

        private TestFilter(List<String> ignoredPaths) {
            super(ignoredPaths);
        }

        private boolean matches(MockHttpServletRequest request) {
            return requiresAuthentication(request, new MockHttpServletResponse());
        }
    }
}
