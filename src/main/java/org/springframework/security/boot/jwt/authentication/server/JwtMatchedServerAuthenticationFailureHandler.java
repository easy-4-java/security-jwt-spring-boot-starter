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
package org.springframework.security.boot.jwt.authentication.server;

import org.springframework.security.boot.biz.authentication.server.MatchedServerAuthenticationFailureHandler;
import org.springframework.security.boot.jwt.exception.*;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

/**
 * Reactive {@link MatchedServerAuthenticationFailureHandler} that supports all JWT-related
 * authentication failure exceptions raised by this starter.
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class JwtMatchedServerAuthenticationFailureHandler implements MatchedServerAuthenticationFailureHandler {

	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), AuthenticationJwtIssuedException.class,
				AuthenticationJwtNotFoundException.class, AuthenticationJwtExpiredException.class,
				AuthenticationJwtInvalidException.class, AuthenticationJwtIncorrectException.class);
	}
    
}