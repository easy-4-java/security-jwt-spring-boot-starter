/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationProcessingFilter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("SecurityJwtAuthzFilterConfiguration Tests")
class SecurityJwtAuthzFilterConfigurationTest {

    @Test
    @DisplayName("Configuration class can be instantiated")
    void testInstantiation() {
        SecurityJwtAuthzFilterConfiguration config = new SecurityJwtAuthzFilterConfiguration();
        assertThat(config).isNotNull();
    }

    @Test
    @DisplayName("JwtAuthzWebSecurityCustomizerAdapter can be constructed and builds filter")
    void testAdapterConstruction() throws Exception {
        SecurityBizProperties bizProperties = new SecurityBizProperties();
        SecurityJwtAuthcProperties authcProperties = new SecurityJwtAuthcProperties();
        SecurityJwtAuthzProperties authzProperties = new SecurityJwtAuthzProperties();
        SecuritySessionMgtProperties sessionMgtProperties = new SecuritySessionMgtProperties();

        SecurityJwtAuthzFilterConfiguration.JwtAuthzWebSecurityCustomizerAdapter adapter =
                new SecurityJwtAuthzFilterConfiguration.JwtAuthzWebSecurityCustomizerAdapter(
                        bizProperties,
                        sessionMgtProperties,
                        authcProperties,
                        authzProperties,
                        emptyProvider(AccessDeniedHandler.class),
                        emptyProvider(LocaleContextFilter.class),
                        providerOf(mock(AuthenticationProvider.class)),
                        emptyProvider(AuthenticationListener.class),
                        emptyProvider(MatchedAuthenticationEntryPoint.class),
                        emptyProvider(MatchedAuthenticationFailureHandler.class),
                        emptyProvider(RequestCache.class),
                        emptyProvider(RememberMeServices.class),
                        emptyProvider(SessionRegistry.class),
                        emptyProvider(SessionAuthenticationStrategy.class)
                );

        assertThat(adapter).isNotNull();
        assertThat(adapter.getSessionMgtProperties()).isSameAs(sessionMgtProperties);

        JwtAuthorizationProcessingFilter filter = adapter.authenticationProcessingFilter();
        assertThat(filter).isNotNull();
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> emptyProvider(Class<T> type) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        when(provider.stream()).thenReturn(Collections.<T>emptyList().stream());
        return provider;
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> providerOf(T value) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        when(provider.stream()).thenReturn(Collections.singletonList(value).stream());
        return provider;
    }
}
