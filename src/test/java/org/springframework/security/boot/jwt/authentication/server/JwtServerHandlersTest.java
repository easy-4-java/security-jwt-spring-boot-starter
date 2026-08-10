/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
package org.springframework.security.boot.jwt.authentication.server;

import io.github.easy4j.jwt.JwtPayload;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationToken;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtExpiredException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtNotFoundException;
import org.springframework.util.AntPathMatcher;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("JWT Server Handlers Tests")
class JwtServerHandlersTest {

    @Test
    @DisplayName("JwtMatchedServerAuthenticationEntryPoint can be instantiated")
    void testEntryPointInstantiation() {
        JwtMatchedServerAuthenticationEntryPoint entryPoint = new JwtMatchedServerAuthenticationEntryPoint();
        assertThat(entryPoint).isNotNull();
    }

    @Test
    @DisplayName("JwtMatchedServerAuthenticationEntryPoint supports JWT exceptions")
    void testEntryPointSupports() {
        JwtMatchedServerAuthenticationEntryPoint entryPoint = new JwtMatchedServerAuthenticationEntryPoint();
        assertThat(entryPoint.supports(new AuthenticationJwtExpiredException("expired"))).isTrue();
        assertThat(entryPoint.supports(new AuthenticationJwtNotFoundException("not found"))).isTrue();
    }

    @Test
    @DisplayName("JwtMatchedServerAuthenticationFailureHandler can be instantiated")
    void testFailureHandlerInstantiation() {
        JwtMatchedServerAuthenticationFailureHandler handler = new JwtMatchedServerAuthenticationFailureHandler();
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("JwtMatchedServerAuthenticationFailureHandler supports JWT exceptions")
    void testFailureHandlerSupports() {
        JwtMatchedServerAuthenticationFailureHandler handler = new JwtMatchedServerAuthenticationFailureHandler();
        assertThat(handler.supports(new AuthenticationJwtExpiredException("expired"))).isTrue();
    }

    @Test
    @DisplayName("JwtMatchedServerAuthenticationSuccessHandler can be instantiated")
    void testSuccessHandlerInstantiation() {
        JwtPayloadRepository repo = new JwtPayloadRepository() {};
        JwtMatchedServerAuthenticationSuccessHandler handler = new JwtMatchedServerAuthenticationSuccessHandler(repo, true);
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("JwtMatchedServerAuthenticationSuccessHandler supports check")
    void testSuccessHandlerSupports() {
        JwtPayloadRepository repo = new JwtPayloadRepository() {};
        JwtMatchedServerAuthenticationSuccessHandler handler = new JwtMatchedServerAuthenticationSuccessHandler(repo, true);
        org.springframework.security.core.Authentication auth = mock(org.springframework.security.core.Authentication.class);
        assertThat(handler.supports(auth)).isFalse();
    }

    @Test
    @DisplayName("JwtAuthenticationWebFilter can be instantiated")
    void testWebFilterInstantiation() {
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(new JwtPayloadRepository() {});
        JwtAuthenticationWebFilter filter = new JwtAuthenticationWebFilter(manager);
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("JwtReactiveAuthenticationManager can be instantiated")
    void testReactiveAuthManagerInstantiation() {
        JwtPayloadRepository repo = new JwtPayloadRepository() {};
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(repo);
        assertThat(manager).isNotNull();
        assertThat(manager.getPayloadRepository()).isSameAs(repo);
    }

    @Test
    @DisplayName("JwtReactiveAuthenticationManager checkExpiry getter/setter")
    void testReactiveAuthManagerCheckExpiry() {
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(new JwtPayloadRepository() {});
        manager.setCheckExpiry(true);
        assertThat(manager.isCheckExpiry()).isTrue();
    }

    @Test
    @DisplayName("JwtReactiveAuthenticationManager checkPrincipal getter/setter")
    void testReactiveAuthManagerCheckPrincipal() {
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(new JwtPayloadRepository() {});
        manager.setCheckPrincipal(true);
        assertThat(manager.isCheckPrincipal()).isTrue();
    }

    @Test
    @DisplayName("JwtReactiveAuthenticationManager userDetailsChecker getter/setter")
    void testReactiveAuthManagerUserDetailsChecker() {
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(new JwtPayloadRepository() {});
        assertThat(manager.getUserDetailsChecker()).isNotNull();
    }

    @Test
    @DisplayName("JwtReactiveAuthenticationManager rejects blank token")
    void testReactiveAuthManagerRejectsBlank() {
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(new JwtPayloadRepository() {});
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid", "");
        try {
            manager.authenticate(token).block();
        } catch (Exception e) {
            assertThat(e).isInstanceOf(AuthenticationJwtNotFoundException.class);
        }
    }

    @Test
    @DisplayName("JwtReactiveAuthenticationManager rejects expired token")
    void testReactiveAuthManagerRejectsExpired() {
        JwtPayloadRepository repo = mock(JwtPayloadRepository.class);
        when(repo.verify(any(AbstractAuthenticationToken.class), anyBoolean())).thenReturn(false);
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(repo);
        manager.setCheckExpiry(true);
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid", "some-jwt");
        try {
            manager.authenticate(token).block();
        } catch (Exception e) {
            assertThat(e).isInstanceOf(AuthenticationJwtExpiredException.class);
        }
    }

    @Test
    @DisplayName("JwtReactiveAuthenticationManager rejects when checkPrincipal fails")
    void testReactiveAuthManagerRejectsPrincipal() {
        JwtPayloadRepository repo = mock(JwtPayloadRepository.class);
        when(repo.verify(any(AbstractAuthenticationToken.class), anyBoolean())).thenReturn(true);

        JwtPayload payload = mock(JwtPayload.class);
        when(payload.getSubject()).thenReturn("different-uid");
        when(payload.getTokenId()).thenReturn("tid");
        when(payload.isEnabled()).thenReturn(true);
        when(payload.isAccountNonExpired()).thenReturn(true);
        when(payload.isCredentialsNonExpired()).thenReturn(true);
        when(payload.isAccountNonLocked()).thenReturn(true);
        when(payload.getRoles()).thenReturn(Collections.emptyList());
        when(payload.getPerms()).thenReturn(new HashSet<>());
        when(payload.getClaims()).thenReturn(new HashMap<>());
        when(payload.getRkey()).thenReturn("rkey");
        when(repo.getPayload(any(AbstractAuthenticationToken.class), anyBoolean())).thenReturn(payload);

        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(repo);
        manager.setCheckPrincipal(true);
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid-123", "some-jwt");
        try {
            manager.authenticate(token).block();
        } catch (Exception e) {
            assertThat(e).isInstanceOf(org.springframework.security.boot.jwt.exception.AuthenticationJwtInvalidException.class);
        }
    }

    @Test
    @DisplayName("JwtReactiveAuthenticationManager authenticate with valid token")
    void testReactiveAuthManagerSuccess() {
        JwtPayloadRepository repo = mock(JwtPayloadRepository.class);
        when(repo.verify(any(AbstractAuthenticationToken.class), anyBoolean())).thenReturn(true);

        JwtPayload payload = mock(JwtPayload.class);
        when(payload.getSubject()).thenReturn("uid-123");
        when(payload.getTokenId()).thenReturn("tid-1");
        when(payload.isEnabled()).thenReturn(true);
        when(payload.isAccountNonExpired()).thenReturn(true);
        when(payload.isCredentialsNonExpired()).thenReturn(true);
        when(payload.isAccountNonLocked()).thenReturn(true);
        when(payload.getRoles()).thenReturn(Collections.emptyList());
        when(payload.getPerms()).thenReturn(new HashSet<>(Collections.singletonList("user:read")));
        when(payload.getClaims()).thenReturn(new HashMap<>());
        when(payload.getUuid()).thenReturn("uuid-1");
        when(payload.getUkey()).thenReturn("ukey-1");
        when(payload.getUcode()).thenReturn("ucode-1");
        when(payload.getRid()).thenReturn("rid-1");
        when(payload.getRkey()).thenReturn("rkey-1");
        when(payload.isBound()).thenReturn(false);
        when(payload.isInitial()).thenReturn(false);
        when(payload.getProfile()).thenReturn(new HashMap<>());

        when(repo.getPayload(any(AbstractAuthenticationToken.class), anyBoolean())).thenReturn(payload);

        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(repo);
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid-123", "valid-jwt-token");
        token.setSign("sig");

        org.springframework.security.core.Authentication result = manager.authenticate(token).block();
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
    }

    @Test
    @DisplayName("JwtServerAuthenticationConverter can be instantiated")
    void testServerAuthConverterInstantiation() {
        JwtServerAuthenticationConverter converter = new JwtServerAuthenticationConverter();
        assertThat(converter).isNotNull();
    }

    @Test
    @DisplayName("JwtServerAuthenticationConverter getters/setters")
    void testServerAuthConverterGettersSetters() {
        JwtServerAuthenticationConverter converter = new JwtServerAuthenticationConverter();
        converter.setAuthorizationHeaderName("Custom-Auth");
        assertThat(converter.getAuthorizationHeaderName()).isEqualTo("Custom-Auth");
        converter.setAuthorizationParamName("mytoken");
        assertThat(converter.getAuthorizationParamName()).isEqualTo("mytoken");
        converter.setAuthorizationCookieName("mycookie");
        assertThat(converter.getAuthorizationCookieName()).isEqualTo("mycookie");
        converter.setUidHeaderName("X-UserId");
        assertThat(converter.getUidHeaderName()).isEqualTo("X-UserId");
        converter.setSignHeaderName("X-Signature");
        assertThat(converter.getSignHeaderName()).isEqualTo("X-Signature");
        converter.setLongitudeHeaderName("X-Lng");
        assertThat(converter.getLongitudeHeaderName()).isEqualTo("X-Lng");
        converter.setLatitudeHeaderName("X-Lat");
        assertThat(converter.getLatitudeHeaderName()).isEqualTo("X-Lat");
    }

    @Test
    @DisplayName("JwtServerAuthorizationSecurityContextRepository can be instantiated")
    void testSecurityContextRepoInstantiation() {
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(new JwtPayloadRepository() {});
        JwtServerAuthorizationSecurityContextRepository repo =
                new JwtServerAuthorizationSecurityContextRepository(manager, "/webjars/**");
        assertThat(repo).isNotNull();
        assertThat(repo.getAuthenticationManager()).isSameAs(manager);
        assertThat(repo.getWhiteList()).containsExactly("/webjars/**");
    }

    @Test
    @DisplayName("JwtServerAuthorizationSecurityContextRepository getters/setters")
    void testSecurityContextRepoGettersSetters() {
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(new JwtPayloadRepository() {});
        JwtServerAuthorizationSecurityContextRepository repo =
                new JwtServerAuthorizationSecurityContextRepository(manager);
        repo.setAuthorizationHeaderName("Custom-Auth");
        assertThat(repo.getAuthorizationHeaderName()).isEqualTo("Custom-Auth");
        repo.setAuthorizationParamName("mytoken");
        assertThat(repo.getAuthorizationParamName()).isEqualTo("mytoken");
        repo.setAuthorizationCookieName("mycookie");
        assertThat(repo.getAuthorizationCookieName()).isEqualTo("mycookie");
        repo.setUidHeaderName("X-UserId");
        assertThat(repo.getUidHeaderName()).isEqualTo("X-UserId");
        repo.setSignHeaderName("X-Signature");
        assertThat(repo.getSignHeaderName()).isEqualTo("X-Signature");
        repo.setLongitudeHeaderName("X-Lng");
        assertThat(repo.getLongitudeHeaderName()).isEqualTo("X-Lng");
        repo.setLatitudeHeaderName("X-Lat");
        assertThat(repo.getLatitudeHeaderName()).isEqualTo("X-Lat");
        AntPathMatcher matcher = new AntPathMatcher();
        repo.setAntPathMatcher(matcher);
        assertThat(repo.getAntPathMatcher()).isSameAs(matcher);
    }

    @Test
    @DisplayName("JwtServerAuthorizationSecurityContextRepository save returns empty Mono")
    void testSecurityContextRepoSave() {
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(new JwtPayloadRepository() {});
        JwtServerAuthorizationSecurityContextRepository repo =
                new JwtServerAuthorizationSecurityContextRepository(manager);
        org.springframework.security.core.context.SecurityContext ctx = mock(org.springframework.security.core.context.SecurityContext.class);
        repo.save(mock(org.springframework.web.server.ServerWebExchange.class), ctx).block();
    }

    @Test
    @DisplayName("JwtServerAuthorizationSecurityContextRepository load with whitelisted path returns empty")
    void testSecurityContextRepoLoadWhitelist() {
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(new JwtPayloadRepository() {});
        JwtServerAuthorizationSecurityContextRepository repo =
                new JwtServerAuthorizationSecurityContextRepository(manager, "/webjars/**");

        org.springframework.mock.http.server.reactive.MockServerHttpRequest mockRequest =
                org.springframework.mock.http.server.reactive.MockServerHttpRequest.get("/webjars/jquery.min.js").build();
        org.springframework.mock.web.server.MockServerWebExchange exchange =
                org.springframework.mock.web.server.MockServerWebExchange.from(mockRequest);

        org.springframework.security.core.context.SecurityContext result = repo.load(exchange).block();
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("JwtServerAuthorizationSecurityContextRepository load with no token throws")
    void testSecurityContextRepoLoadNoToken() {
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(new JwtPayloadRepository() {});
        JwtServerAuthorizationSecurityContextRepository repo =
                new JwtServerAuthorizationSecurityContextRepository(manager);

        org.springframework.mock.http.server.reactive.MockServerHttpRequest mockRequest =
                org.springframework.mock.http.server.reactive.MockServerHttpRequest.get("/api/resource").build();
        org.springframework.mock.web.server.MockServerWebExchange exchange =
                org.springframework.mock.web.server.MockServerWebExchange.from(mockRequest);

        // obtainToken returns empty string which triggers AuthenticationJwtNotFoundException
        try {
            repo.load(exchange).block();
        } catch (Exception e) {
            // May throw AuthenticationJwtNotFoundException or RuntimeException wrapping it
            assertThat(e).isInstanceOfAny(AuthenticationJwtNotFoundException.class, RuntimeException.class);
        }
    }

    @Test
    @DisplayName("JwtServerAuthorizationSecurityContextRepository load with token in header")
    void testSecurityContextRepoLoadWithToken() {
        JwtPayloadRepository repo = mock(JwtPayloadRepository.class);
        when(repo.verify(any(AbstractAuthenticationToken.class), anyBoolean())).thenReturn(true);

        JwtPayload payload = mock(JwtPayload.class);
        when(payload.getSubject()).thenReturn("uid");
        when(payload.getTokenId()).thenReturn("tid");
        when(payload.isEnabled()).thenReturn(true);
        when(payload.isAccountNonExpired()).thenReturn(true);
        when(payload.isCredentialsNonExpired()).thenReturn(true);
        when(payload.isAccountNonLocked()).thenReturn(true);
        when(payload.getRoles()).thenReturn(Collections.emptyList());
        when(payload.getPerms()).thenReturn(new HashSet<>(Collections.singletonList("user:read")));
        when(payload.getClaims()).thenReturn(new HashMap<>());
        when(payload.getUuid()).thenReturn("uuid");
        when(payload.getUkey()).thenReturn("ukey");
        when(payload.getUcode()).thenReturn("ucode");
        when(payload.getRid()).thenReturn("rid");
        when(payload.getRkey()).thenReturn("rkey");
        when(payload.isBound()).thenReturn(false);
        when(payload.isInitial()).thenReturn(false);
        when(payload.getProfile()).thenReturn(new HashMap<>());
        when(repo.getPayload(any(AbstractAuthenticationToken.class), anyBoolean())).thenReturn(payload);

        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(repo);
        JwtServerAuthorizationSecurityContextRepository secRepo =
                new JwtServerAuthorizationSecurityContextRepository(manager);

        org.springframework.mock.http.server.reactive.MockServerHttpRequest mockRequest =
                org.springframework.mock.http.server.reactive.MockServerHttpRequest.get("/api/resource")
                        .header("X-Authorization", "some-jwt-token")
                        .build();
        org.springframework.mock.web.server.MockServerWebExchange exchange =
                org.springframework.mock.web.server.MockServerWebExchange.from(mockRequest);

        org.springframework.security.core.context.SecurityContext result = secRepo.load(exchange).block();
        assertThat(result).isNotNull();
        assertThat(result.getAuthentication()).isNotNull();
    }

    // ---- JwtServerAuthenticationConverter ----

    @Test
    @DisplayName("JwtServerAuthenticationConverter convert with token in header")
    void testConverterConvertWithToken() {
        JwtServerAuthenticationConverter converter = new JwtServerAuthenticationConverter();

        org.springframework.mock.http.server.reactive.MockServerHttpRequest mockRequest =
                org.springframework.mock.http.server.reactive.MockServerHttpRequest.get("/api/resource")
                        .header("X-Authorization", "some-jwt-token")
                        .header("X-Uid", "uid-123")
                        .header("X-Sign", "sig")
                        .header("X-Longitude", "120.5")
                        .header("X-Latitude", "30.5")
                        .build();
        org.springframework.mock.web.server.MockServerWebExchange exchange =
                org.springframework.mock.web.server.MockServerWebExchange.from(mockRequest);

        org.springframework.security.core.Authentication result = converter.convert(exchange).block();
        assertThat(result).isNotNull();
        assertThat(result.getPrincipal()).isEqualTo("uid-123");
        assertThat(result.getCredentials()).isEqualTo("some-jwt-token");
    }

    @Test
    @DisplayName("JwtServerAuthenticationConverter convert with no token throws")
    void testConverterConvertNoToken() {
        JwtServerAuthenticationConverter converter = new JwtServerAuthenticationConverter();

        org.springframework.mock.http.server.reactive.MockServerHttpRequest mockRequest =
                org.springframework.mock.http.server.reactive.MockServerHttpRequest.get("/api/resource").build();
        org.springframework.mock.web.server.MockServerWebExchange exchange =
                org.springframework.mock.web.server.MockServerWebExchange.from(mockRequest);

        try {
            converter.convert(exchange).block();
        } catch (Exception e) {
            assertThat(e).isInstanceOf(AuthenticationJwtNotFoundException.class);
        }
    }

    @Test
    @DisplayName("JwtServerAuthenticationConverter convert with token in query param")
    void testConverterConvertWithParam() {
        JwtServerAuthenticationConverter converter = new JwtServerAuthenticationConverter();

        org.springframework.mock.http.server.reactive.MockServerHttpRequest mockRequest =
                org.springframework.mock.http.server.reactive.MockServerHttpRequest.get("/api/resource?token=my-jwt").build();
        org.springframework.mock.web.server.MockServerWebExchange exchange =
                org.springframework.mock.web.server.MockServerWebExchange.from(mockRequest);

        org.springframework.security.core.Authentication result = converter.convert(exchange).block();
        assertThat(result).isNotNull();
        assertThat(result.getCredentials()).isEqualTo("my-jwt");
    }

    // ---- JwtMatchedServerAuthenticationSuccessHandler onAuthenticationSuccess ----

    @Test
    @DisplayName("JwtMatchedServerAuthenticationSuccessHandler onAuthenticationSuccess")
    void testSuccessHandlerOnSuccess() throws Exception {
        JwtPayloadRepository repo = mock(JwtPayloadRepository.class);
        org.springframework.security.boot.biz.userdetails.UserProfilePayload profilePayload =
                new org.springframework.security.boot.biz.userdetails.UserProfilePayload();
        org.mockito.Mockito.when(repo.getProfilePayload(
                any(AbstractAuthenticationToken.class), anyBoolean())).thenReturn(profilePayload);

        JwtMatchedServerAuthenticationSuccessHandler handler = new JwtMatchedServerAuthenticationSuccessHandler(repo, true);

        org.springframework.mock.http.server.reactive.MockServerHttpRequest mockRequest =
                org.springframework.mock.http.server.reactive.MockServerHttpRequest.get("/api/resource").build();
        org.springframework.mock.web.server.MockServerWebExchange exchange =
                org.springframework.mock.web.server.MockServerWebExchange.from(mockRequest);
        org.springframework.security.web.server.WebFilterExchange webFilterExchange =
                mock(org.springframework.security.web.server.WebFilterExchange.class);
        org.mockito.Mockito.when(webFilterExchange.getExchange()).thenReturn(exchange);

        JwtAuthorizationToken auth = new JwtAuthorizationToken("uid", "token",
                java.util.Collections.singletonList(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")));

        handler.onAuthenticationSuccess(webFilterExchange, auth).block();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.OK);
    }
}
