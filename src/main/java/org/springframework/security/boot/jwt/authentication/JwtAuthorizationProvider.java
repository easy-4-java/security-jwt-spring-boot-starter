package org.springframework.security.boot.jwt.authentication;

import io.github.easy4j.jwt.JwtClaims;
import io.github.easy4j.jwt.JwtPayload;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtExpiredException;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Authentication provider that authorises incoming requests by verifying the supplied JWT and
 * resolving the user principal and authorities from its payload.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class JwtAuthorizationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
	private final JwtPayloadRepository payloadRepository;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private boolean checkExpiry = false;
    private boolean checkPrincipal = false;
    
    /**
     * Create a new provider backed by the given {@link JwtPayloadRepository}.
     * @param payloadRepository the repository used to verify tokens and resolve their payload
     */
    public JwtAuthorizationProvider(final JwtPayloadRepository payloadRepository) {
        this.payloadRepository = payloadRepository;
    }

    /**
     * Authenticate the supplied {@link JwtAuthorizationToken}. The returned token is what is
     * ultimately stored on the {@code SecurityContextHolder} via
     * {@code SecurityContextHolder.getContext().setAuthentication(authResult)}.
     * @param authentication the {@link JwtAuthorizationToken} to authenticate
     * @return the authenticated {@link JwtAuthorizationToken}
     * @throws AuthenticationException if authentication fails
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
    	
    	//String uid = (String) authentication.getPrincipal();
        String token = (String) authentication.getCredentials();

        if (StringUtils.isBlank(token)) {
			logger.debug("No JWT found in request.");
			throw new AuthenticationJwtNotFoundException("No JWT found in request.");
		}
		
		JwtAuthorizationToken jwtToken = (JwtAuthorizationToken) authentication;
		
		// 检查token有效性
		if(isCheckExpiry() && !getPayloadRepository().verify(jwtToken, isCheckExpiry())) {
			throw new AuthenticationJwtExpiredException("Token Expired");
		}
		
		// 解析Token载体info
		JwtPayload payload = getPayloadRepository().getPayload(jwtToken, checkExpiry);

		// 检查token有效性
		if(this.isCheckExpiry() && !getPayloadRepository().verify(jwtToken, isCheckExpiry())) {
			throw new AuthenticationJwtExpiredException("Token Expired");
		}
		
		Set<GrantedAuthority> grantedAuthorities = new HashSet<GrantedAuthority>();
		
		// 角色必须是ROLE_开头，可以在数据库中sets
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_"+ payload.getRkey());
        grantedAuthorities.add(grantedAuthority);
   		
   		// userpermission标记集合
   		Set<String> perms = payload.getPerms();
		for (String perm : perms ) {
			GrantedAuthority authority = new SimpleGrantedAuthority(perm);
            grantedAuthorities.add(authority);
		}
		
		Map<String, Object> claims = payload.getClaims();
		
		String uid = StringUtils.defaultString(MapUtils.getString(claims, JwtClaims.UID), payload.getSubject());
		
		SecurityPrincipal principal = new SecurityPrincipal(uid, payload.getTokenId(), payload.isEnabled(),
				payload.isAccountNonExpired(), payload.isCredentialsNonExpired(), payload.isAccountNonLocked(),
				grantedAuthorities);
	
		principal.setUid(uid);
		principal.setUuid(payload.getUuid());
		principal.setUkey(payload.getUkey());
		principal.setUcode(payload.getUcode());
		principal.setPerms(new HashSet<String>(perms));
		principal.setRid(payload.getRid());
		principal.setRkey(payload.getRkey());
		principal.setRoles(payload.getRoles());
		principal.setBound(payload.isBound());
		principal.setInitial(payload.isInitial());
		principal.setProfile(payload.getProfile());
		principal.setSign(jwtToken.getSign());
		principal.setLongitude(jwtToken.getLongitude());
		principal.setLatitude(jwtToken.getLatitude());
		
        // User Status Check
        getUserDetailsChecker().check(principal);
        
        JwtAuthorizationToken authenticationToken = new JwtAuthorizationToken(principal, payload, principal.getAuthorities());        	
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
        return (JwtAuthorizationToken.class.isAssignableFrom(authentication));
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
	 * Returns the payload repository.
	 *
	 * @return the payload repository
	 */
	public JwtPayloadRepository getPayloadRepository() {
		return payloadRepository;
	}

	/**
	 * Returns the check expiry.
	 *
	 * @return the check expiry
	 */
	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	/**
	 * Sets the check expiry.
	 *
	 * @param checkExpiry the check expiry
	 */
	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}

	/**
	 * Returns the check principal.
	 *
	 * @return the check principal
	 */
	public boolean isCheckPrincipal() {
		return checkPrincipal;
	}

	/**
	 * Sets the check principal.
	 *
	 * @param checkPrincipal the check principal
	 */
	public void setCheckPrincipal(boolean checkPrincipal) {
		this.checkPrincipal = checkPrincipal;
	}
    
}
