package org.springframework.security.boot.jwt.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * Filter that processes JWT authentication (login) requests submitted via {@code POST /login/jwt}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class JwtAuthenticationProcessingFilter extends PostRequestAuthenticationProcessingFilter {
	
	/**
	 * Create a new filter matching {@code POST /login/jwt}.
	 * @param objectMapper the {@link ObjectMapper} used to (de)serialise request and response bodies
	 */
	public JwtAuthenticationProcessingFilter(ObjectMapper objectMapper) {
		super(objectMapper, PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/login/jwt"));
	}
	
	/**
	 * set Details.
	 *
	 * @param request the request
	 * @param authRequest the auth request
	 */
	@Override
	protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
		super.setDetails(request, authRequest);
		JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authRequest;
		jwtToken.setLongitude(this.obtainLongitude(request));
		jwtToken.setLatitude(this.obtainLatitude(request));
		jwtToken.setSign(this.obtainSign(request));
	}
	
	/**
	 * authentication Token.
	 *
	 * @param username the username
	 * @param password the password
	 * @return the result
	 */
	@Override
	protected AbstractAuthenticationToken authenticationToken(String username, String password) {
		return new JwtAuthenticationToken( username, password);
	}
	
}
