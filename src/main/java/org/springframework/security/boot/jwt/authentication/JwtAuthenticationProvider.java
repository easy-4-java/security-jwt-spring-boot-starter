package org.springframework.security.boot.jwt.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Authentication provider for username/password login requests that produce a JWT.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class JwtAuthenticationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
    /**
     * Create a new provider backed by the given user-details service and password encoder.
     * @param userDetailsService the service used to load user details
     * @param passwordEncoder the encoder used to verify the supplied password
     */
    public JwtAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService, final PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Authenticate the supplied {@link JwtAuthenticationToken}. The returned token is what is
     * ultimately stored on the {@code SecurityContextHolder} via
     * {@code SecurityContextHolder.getContext().setAuthentication(authResult)}.
     * @param authentication the {@link JwtAuthenticationToken} to authenticate
     * @return the authenticated {@link JwtAuthenticationToken}
     * @throws AuthenticationException if authentication fails
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
    	
    	JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();
        
		if (!StringUtils.hasLength(username)) {
			logger.debug("No principal found in request.");
			throw new BadCredentialsException("No principal found in request.");
		}

		if (!StringUtils.hasLength(password)) {
			logger.debug("No credentials found in request.");
			throw new BadCredentialsException("No credentials found in request.");
		}
        
        UserDetails ud = getUserDetailsService().loadUserDetails(authentication);
        if (!passwordEncoder.matches(password, ud.getPassword())) {
            throw new BadCredentialsException("Authentication Failed. Username or Password not valid.");
        }
        
        // User Status Check
        getUserDetailsChecker().check(ud);
        
        JwtAuthenticationToken authenticationToken = null;
        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
        	SecurityPrincipal principal = (SecurityPrincipal) ud;
        	principal.setSign(jwtToken.getSign());
    		principal.setLongitude(jwtToken.getLongitude());
    		principal.setLatitude(jwtToken.getLatitude());
        	authenticationToken = new JwtAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());        	
        } else {
        	authenticationToken = new JwtAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
		}
        authenticationToken.setDetails(authentication.getDetails());
        
        return authenticationToken;
    }

    /**
     * Determines whether supports.
     *
     * @param authentication the authentication
     * @return the result
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
    
    /**
     * Sets the user details checker.
     *
     * @param userDetailsChecker the user details checker
     */
    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	/**
	 * Returns the user details checker.
	 *
	 * @return the user details checker
	 */
	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	/**
	 * Returns the password encoder.
	 *
	 * @return the password encoder
	 */
	public PasswordEncoder getPasswordEncoder() {
		return passwordEncoder;
	}

	/**
	 * Returns the user details service.
	 *
	 * @return the user details service
	 */
	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}
	
    
}
