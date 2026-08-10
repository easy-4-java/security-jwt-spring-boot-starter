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

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }
        super.setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }
    
    @Override
    public void eraseCredentials() {        
        super.eraseCredentials();
        this.credentials = null;
    }

	public String getSign() {
		return sign;
	}

	public void setSign(String sign) {
		this.sign = sign;
	}

	public double getLongitude() {
		return longitude;
	}

	public void setLongitude(double longitude) {
		this.longitude = longitude;
	}

	public double getLatitude() {
		return latitude;
	}

	public void setLatitude(double latitude) {
		this.latitude = latitude;
	}
    
}
