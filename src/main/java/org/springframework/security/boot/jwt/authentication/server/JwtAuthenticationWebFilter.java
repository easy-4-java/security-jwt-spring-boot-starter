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

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;

/**
 * Reactive {@link AuthenticationWebFilter} that intercepts requests and authenticates them
 * using the supplied {@link ReactiveAuthenticationManager}.
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class JwtAuthenticationWebFilter extends AuthenticationWebFilter {

	/**
	 * Create a new filter using the given authentication manager.
	 * @param authenticationManager the manager used to authenticate incoming requests
	 */
	public JwtAuthenticationWebFilter(ReactiveAuthenticationManager authenticationManager) {
		super(authenticationManager);
	}
	
}