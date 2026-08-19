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
package org.springframework.security.boot.jwt.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Authentication token carrying the username and password submitted during JWT login.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

	// ~ Instance fields
	// ================================================================================================

	private final Object principal;
	private Object credentials;
	/**
	 * Optional request signature parameter.
	 */
	private String sign;
	/**
	 * Optional most recent longitude reported by the user.
	 */
	private double longitude;
	/**
	 * Optional most recent latitude reported by the user.
	 */
	private double latitude;
	
	// ~ Constructors
	// ===================================================================================================

	/**
	 * This constructor can be safely used by any code that wishes to create a
	 * <code>JwtAuthenticationToken</code>, as the {@link #isAuthenticated()}
	 * will return <code>false</code>.
	 *
	 */
	public JwtAuthenticationToken(Object principal, Object credentials) {
		super((Collection<? extends GrantedAuthority>) null);
		this.principal = principal;
		this.credentials = credentials;
		setAuthenticated(false);
	}

	/**
	 * This constructor should only be used by <code>AuthenticationManager</code> or
	 * <code>AuthenticationProvider</code> implementations that are satisfied with
	 * producing a trusted (i.e. {@link #isAuthenticated()} = <code>true</code>)
	 * authentication token.
	 *
	 * @param principal
	 * @param credentials
	 * @param authorities
	 */
	public JwtAuthenticationToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		super.setAuthenticated(true); // must use super, as we override
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * Returns the credentials.
	 *
	 * @return the credentials
	 */
	public Object getCredentials() {
		return this.credentials;
	}

	/**
	 * Returns the principal.
	 *
	 * @return the principal
	 */
	public Object getPrincipal() {
		return this.principal;
	}

	/**
	 * Sets the authenticated.
	 *
	 * @param isAuthenticated the is authenticated
	 * @throws IllegalArgumentException if an error occurs
	 */
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (isAuthenticated) {
			throw new IllegalArgumentException(
					"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		}

		super.setAuthenticated(false);
	}

	/**
	 * erase Credentials.
	 *
	 */
	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		credentials = null;
	}
	
	/**
	 * Returns the sign.
	 *
	 * @return the sign
	 */
	public String getSign() {
		return sign;
	}

	/**
	 * Sets the sign.
	 *
	 * @param sign the sign
	 */
	public void setSign(String sign) {
		this.sign = sign;
	}

	/**
	 * Returns the longitude.
	 *
	 * @return the longitude
	 */
	public double getLongitude() {
		return longitude;
	}

	/**
	 * Sets the longitude.
	 *
	 * @param longitude the longitude
	 */
	public void setLongitude(double longitude) {
		this.longitude = longitude;
	}

	/**
	 * Returns the latitude.
	 *
	 * @return the latitude
	 */
	public double getLatitude() {
		return latitude;
	}

	/**
	 * Sets the latitude.
	 *
	 * @param latitude the latitude
	 */
	public void setLatitude(double latitude) {
		this.latitude = latitude;
	}

}
