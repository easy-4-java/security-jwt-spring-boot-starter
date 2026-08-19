package org.springframework.security.boot.jwt.authentication;

import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.jwt.exception.*;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

/**
 * {@link MatchedAuthenticationFailureHandler} that supports all JWT-related authentication and
 * authorization failure exceptions raised by this starter.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class JwtMatchedAuthcOrAuthzFailureHandler implements MatchedAuthenticationFailureHandler {
	
	/**
	 * Determines whether supports.
	 *
	 * @param e the e
	 * @return the result
	 */
	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), AuthenticationJwtIssuedException.class,
				AuthenticationJwtNotFoundException.class, AuthenticationJwtExpiredException.class,
				AuthenticationJwtInvalidException.class, AuthenticationJwtIncorrectException.class);
	}
	
}
