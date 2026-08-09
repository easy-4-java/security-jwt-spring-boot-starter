/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
package org.springframework.security.boot;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.jwt.authentication.JwtAuthenticationProcessingFilter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("SecurityJwtAuthcFilterConfiguration Tests")
class SecurityJwtAuthcFilterConfigurationTest {

    @Test
    @DisplayName("Configuration class can be instantiated")
    void testInstantiation() {
        SecurityJwtAuthcFilterConfiguration config = new SecurityJwtAuthcFilterConfiguration();
        assertThat(config).isNotNull();
    }

    @Test
    @DisplayName("JwtAuthcWebSecurityCustomizerAdapter can be constructed and builds filter")
    void testAdapterConstruction() throws Exception {
        SecurityBizProperties bizProperties = new SecurityBizProperties();
        SecurityJwtAuthcProperties authcProperties = new SecurityJwtAuthcProperties();
        SecuritySessionMgtProperties sessionMgtProperties = new SecuritySessionMgtProperties();

        SecurityJwtAuthcFilterConfiguration.JwtAuthcWebSecurityCustomizerAdapter adapter =
                new SecurityJwtAuthcFilterConfiguration.JwtAuthcWebSecurityCustomizerAdapter(
                        bizProperties,
                        authcProperties,
                        sessionMgtProperties,
                        emptyProvider(AccessDeniedHandler.class),
                        emptyProvider(LocaleContextFilter.class),
                        providerOf(mock(AuthenticationProvider.class)),
                        emptyProvider(AuthenticationListener.class),
                        emptyProvider(AuthenticatingFailureCounter.class),
                        emptyProvider(MatchedAuthenticationEntryPoint.class),
                        emptyProvider(MatchedAuthenticationSuccessHandler.class),
                        emptyProvider(MatchedAuthenticationFailureHandler.class),
                        emptyProvider(CaptchaResolver.class),
                        providerOf(new ObjectMapper()),
                        emptyProvider(RememberMeServices.class),
                        emptyProvider(SessionAuthenticationStrategy.class)
                );

        assertThat(adapter).isNotNull();
        assertThat(adapter.getSessionMgtProperties()).isSameAs(sessionMgtProperties);

        JwtAuthenticationProcessingFilter filter = adapter.authenticationProcessingFilter();
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
