package org.springframework.security.boot.jwt.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;
/**
 * Thrown when the JWT presented for authorization is malformed or otherwise incorrect.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class AuthenticationJwtIncorrectException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationJwtIncorrectException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationJwtIncorrectException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_INCORRECT, msg);
	}

	/**
	 * Constructs an <code>AuthenticationJwtIncorrectException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationJwtIncorrectException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_INCORRECT, msg, t);
	}
}
