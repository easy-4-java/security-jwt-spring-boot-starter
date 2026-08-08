package org.springframework.security.boot.jwt.authentication;

import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.jwt.exception.*;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

/**
 * Jwt认证、授权 (authorization) 失败处理器
 * @author [@Loong Wan](https://github.com/loong10k)
 */
public class JwtMatchedAuthcOrAuthzFailureHandler implements MatchedAuthenticationFailureHandler {
	
	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), AuthenticationJwtIssuedException.class,
				AuthenticationJwtNotFoundException.class, AuthenticationJwtExpiredException.class,
				AuthenticationJwtInvalidException.class, AuthenticationJwtIncorrectException.class);
	}
	
}
