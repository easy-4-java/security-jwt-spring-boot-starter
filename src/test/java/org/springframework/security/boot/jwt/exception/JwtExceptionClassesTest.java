/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
package org.springframework.security.boot.jwt.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JWT Exception Classes Tests")
class JwtExceptionClassesTest {

    @Test
    @DisplayName("AuthenticationJwtExpiredException with message")
    void testExpiredException() {
        AuthenticationJwtExpiredException ex = new AuthenticationJwtExpiredException("Token expired");
        assertThat(ex).isNotNull();
        assertThat(ex.getMessage()).isEqualTo("Token expired");
    }

    @Test
    @DisplayName("AuthenticationJwtExpiredException with message and cause")
    void testExpiredExceptionWithCause() {
        RuntimeException cause = new RuntimeException("root cause");
        AuthenticationJwtExpiredException ex = new AuthenticationJwtExpiredException("Token expired", cause);
        assertThat(ex.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("AuthenticationJwtIncorrectException with message")
    void testIncorrectException() {
        AuthenticationJwtIncorrectException ex = new AuthenticationJwtIncorrectException("Token incorrect");
        assertThat(ex).isNotNull();
        assertThat(ex.getMessage()).isEqualTo("Token incorrect");
    }

    @Test
    @DisplayName("AuthenticationJwtIncorrectException with message and cause")
    void testIncorrectExceptionWithCause() {
        RuntimeException cause = new RuntimeException("root cause");
        AuthenticationJwtIncorrectException ex = new AuthenticationJwtIncorrectException("Token incorrect", cause);
        assertThat(ex.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("AuthenticationJwtInvalidException with message")
    void testInvalidException() {
        AuthenticationJwtInvalidException ex = new AuthenticationJwtInvalidException("Token invalid");
        assertThat(ex).isNotNull();
        assertThat(ex.getMessage()).isEqualTo("Token invalid");
    }

    @Test
    @DisplayName("AuthenticationJwtInvalidException with message and cause")
    void testInvalidExceptionWithCause() {
        RuntimeException cause = new RuntimeException("root cause");
        AuthenticationJwtInvalidException ex = new AuthenticationJwtInvalidException("Token invalid", cause);
        assertThat(ex.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("AuthenticationJwtIssuedException with message")
    void testIssuedException() {
        AuthenticationJwtIssuedException ex = new AuthenticationJwtIssuedException("Token just issued");
        assertThat(ex).isNotNull();
        assertThat(ex.getMessage()).isEqualTo("Token just issued");
    }

    @Test
    @DisplayName("AuthenticationJwtIssuedException with message and cause")
    void testIssuedExceptionWithCause() {
        RuntimeException cause = new RuntimeException("root cause");
        AuthenticationJwtIssuedException ex = new AuthenticationJwtIssuedException("Token just issued", cause);
        assertThat(ex.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("AuthenticationJwtNotFoundException with message")
    void testNotFoundException() {
        AuthenticationJwtNotFoundException ex = new AuthenticationJwtNotFoundException("Token not found");
        assertThat(ex).isNotNull();
        assertThat(ex.getMessage()).isEqualTo("Token not found");
    }

    @Test
    @DisplayName("AuthenticationJwtNotFoundException with message and cause")
    void testNotFoundExceptionWithCause() {
        RuntimeException cause = new RuntimeException("root cause");
        AuthenticationJwtNotFoundException ex = new AuthenticationJwtNotFoundException("Token not found", cause);
        assertThat(ex.getCause()).isSameAs(cause);
    }
}
