/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
package org.springframework.security.boot.jwt.authentication;

import io.github.easy4j.jwt.JwtPayload;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtNotFoundException;
import org.springframework.security.core.userdetails.UserDetailsChecker;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("JwtAuthorizationProvider Tests")
class JwtAuthorizationProviderTest {

    @Test
    @DisplayName("Instance can be created with payload repository")
    void testInstantiation() {
        JwtPayloadRepository repo = new JwtPayloadRepository() {};
        JwtAuthorizationProvider provider = new JwtAuthorizationProvider(repo);
        assertThat(provider).isNotNull();
        assertThat(provider.getPayloadRepository()).isSameAs(repo);
    }

    @Test
    @DisplayName("supports JwtAuthorizationToken")
    void testSupports() {
        JwtAuthorizationProvider provider = new JwtAuthorizationProvider(new JwtPayloadRepository() {});
        assertThat(provider.supports(JwtAuthorizationToken.class)).isTrue();
        assertThat(provider.supports(org.springframework.security.authentication.UsernamePasswordAuthenticationToken.class)).isFalse();
    }

    @Test
    @DisplayName("checkExpiry getter/setter round-trip")
    void testCheckExpiry() {
        JwtAuthorizationProvider provider = new JwtAuthorizationProvider(new JwtPayloadRepository() {});
        provider.setCheckExpiry(true);
        assertThat(provider.isCheckExpiry()).isTrue();
        provider.setCheckExpiry(false);
        assertThat(provider.isCheckExpiry()).isFalse();
    }

    @Test
    @DisplayName("checkPrincipal getter/setter round-trip")
    void testCheckPrincipal() {
        JwtAuthorizationProvider provider = new JwtAuthorizationProvider(new JwtPayloadRepository() {});
        provider.setCheckPrincipal(true);
        assertThat(provider.isCheckPrincipal()).isTrue();
    }

    @Test
    @DisplayName("getUserDetailsChecker returns default checker")
    void testGetUserDetailsChecker() {
        JwtAuthorizationProvider provider = new JwtAuthorizationProvider(new JwtPayloadRepository() {});
        UserDetailsChecker checker = provider.getUserDetailsChecker();
        assertThat(checker).isNotNull();
        assertThat(checker).isInstanceOf(AccountStatusUserDetailsChecker.class);
    }

    @Test
    @DisplayName("setUserDetailsChecker stores checker")
    void testSetUserDetailsChecker() {
        JwtAuthorizationProvider provider = new JwtAuthorizationProvider(new JwtPayloadRepository() {});
        UserDetailsChecker custom = new AccountStatusUserDetailsChecker();
        provider.setUserDetailsChecker(custom);
        assertThat(provider.getUserDetailsChecker()).isSameAs(custom);
    }

    @Test
    @DisplayName("authenticate throws exception for blank token")
    void testAuthenticateBlankToken() {
        JwtPayloadRepository repo = new JwtPayloadRepository() {};
        JwtAuthorizationProvider provider = new JwtAuthorizationProvider(repo);
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid", "");
        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(AuthenticationJwtNotFoundException.class);
    }

    @Test
    @DisplayName("authenticate succeeds with valid token and mocked payload")
    void testAuthenticateSuccess() {
        JwtPayloadRepository repo = mock(JwtPayloadRepository.class);
        when(repo.verify(org.mockito.ArgumentMatchers.<AbstractAuthenticationToken>any(), anyBoolean())).thenReturn(true);

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

        when(repo.getPayload(org.mockito.ArgumentMatchers.<AbstractAuthenticationToken>any(), anyBoolean())).thenReturn(payload);

        JwtAuthorizationProvider provider = new JwtAuthorizationProvider(repo);
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid-123", "valid-jwt-token");
        token.setSign("sig");
        token.setLongitude(120.0);
        token.setLatitude(30.0);

        JwtAuthorizationToken result = (JwtAuthorizationToken) provider.authenticate(token);
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
    }

    @Test
    @DisplayName("authenticate with checkExpiry=true and valid token")
    void testAuthenticateWithCheckExpiry() {
        JwtPayloadRepository repo = mock(JwtPayloadRepository.class);
        when(repo.verify(org.mockito.ArgumentMatchers.<AbstractAuthenticationToken>any(), anyBoolean())).thenReturn(true);

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

        when(repo.getPayload(org.mockito.ArgumentMatchers.<AbstractAuthenticationToken>any(), anyBoolean())).thenReturn(payload);

        JwtAuthorizationProvider provider = new JwtAuthorizationProvider(repo);
        provider.setCheckExpiry(true);
        JwtAuthorizationToken token = new JwtAuthorizationToken("uid-123", "valid-jwt-token");

        JwtAuthorizationToken result = (JwtAuthorizationToken) provider.authenticate(token);
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
    }
}
