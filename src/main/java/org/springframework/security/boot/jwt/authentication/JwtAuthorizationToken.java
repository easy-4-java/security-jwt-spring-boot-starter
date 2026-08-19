package org.springframework.security.boot.jwt.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Authentication token carrying the JWT used to authorise an incoming request.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class JwtAuthorizationToken extends AbstractAuthenticationToken {

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
    
	/**
	 * Create an unauthenticated token with the given principal and credentials.
	 * @param principal the principal (typically the user id)
	 * @param credentials the credentials (the JWT)
	 */
    public JwtAuthorizationToken( Object principal, Object credentials) {
        super((Collection<? extends GrantedAuthority>) null);
        this.principal = principal;
        this.credentials = credentials;
        this.setAuthenticated(false);
    }

    /**
     * Create an authenticated token with the given principal, credentials and authorities.
     * @param principal the authenticated principal
     * @param credentials the credentials (the JWT)
     * @param authorities the granted authorities
     */
    public JwtAuthorizationToken( Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.eraseCredentials();
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true);
    }

    /**
     * Sets the authenticated.
     *
     * @param authenticated the authenticated
     */
    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }
        super.setAuthenticated(false);
    }

    /**
     * Returns the credentials.
     *
     * @return the credentials
     */
    @Override
    public Object getCredentials() {
        return credentials;
    }

    /**
     * Returns the principal.
     *
     * @return the principal
     */
    @Override
    public Object getPrincipal() {
        return this.principal;
    }
    
    /**
     * erase Credentials.
     *
     */
    @Override
    public void eraseCredentials() {        
        super.eraseCredentials();
        this.credentials = null;
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
