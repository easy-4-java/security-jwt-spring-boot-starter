package org.springframework.security.boot.jwt.authentication.server;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.boot.jwt.authentication.JwtAuthorizationToken;
import org.springframework.security.boot.jwt.exception.AuthenticationJwtNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;
import java.util.stream.Stream;

/**
 * Reactive {@link ServerSecurityContextRepository} that extracts the JWT from the incoming
 * request, uses the {@code ReactiveAuthenticationManager} to build an
 * {@code Authentication}, and stores the result in a {@code SecurityContext}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class JwtServerAuthorizationSecurityContextRepository implements ServerSecurityContextRepository {
	
	public static final String DEFAULT_LONGITUDE_LATITUDE = "0.000000";
	
	/**
	 * HTTP Authorization Param, equal to <code>token</code>
	 */
	public static final String AUTHORIZATION_PARAM = "token";
	/**
	 * HTTP Authorization header, equal to <code>X-Authorization</code>
	 */
	public static final String AUTHORIZATION_HEADER = "X-Authorization";
	/**
	 * HTTP Authorization header, equal to <code>X-Uid</code>
	 */
	public static final String UID_HEADER = "X-Uid";
	/**
	 * HTTP Authorization header, equal to <code>X-Sign</code>
	 */
	public static final String SIGN_HEADER = "X-Sign";
	/**
	 * HTTP Authorization header, equal to <code>X-Longitude</code>
	 */
	public static final String LONGITUDE_HEADER = "X-Longitude";
	/**
	 * HTTP Authorization header, equal to <code>X-Latitude</code>
	 */
	public static final String LATITUDE_HEADER = "X-Latitude";

	private String authorizationHeaderName = AUTHORIZATION_HEADER;
	private String authorizationParamName = AUTHORIZATION_PARAM;
	private String authorizationCookieName = AUTHORIZATION_PARAM;
	private String uidHeaderName = UID_HEADER;
	private String signHeaderName = SIGN_HEADER;
	private String longitudeHeaderName = LONGITUDE_HEADER;
	private String latitudeHeaderName = LATITUDE_HEADER;

	private ReactiveAuthenticationManager authenticationManager;
	private String[] whiteList;
	private AntPathMatcher antPathMatcher = new AntPathMatcher();

	/**
	 * Constructs a new jwt server authorization security context repository instance.
	 *
	 * @param authenticationManager the authentication manager
	 * @param whiteList the white list
	 */
	public JwtServerAuthorizationSecurityContextRepository(ReactiveAuthenticationManager authenticationManager, String... whiteList) {
		this.authenticationManager = authenticationManager;
		this.whiteList = whiteList;
	}

	/**
	 * save.
	 *
	 * @param serverWebExchange the server web exchange
	 * @param securityContext the security context
	 * @return the result
	 */
	@Override
	public Mono<Void> save(ServerWebExchange serverWebExchange, SecurityContext securityContext) {
		return Mono.empty();
	}

	/**
	 * load.
	 *
	 * @param serverWebExchange the server web exchange
	 * @return the result
	 */
	@Override
	public Mono<SecurityContext> load(ServerWebExchange serverWebExchange) {
		ServerHttpRequest request = serverWebExchange.getRequest();
		boolean match = Stream.of(whiteList).anyMatch(path -> getAntPathMatcher().match(path, request.getPath().toString()));
		if (match){
			return Mono.empty();
		}
		return Mono.just(request).flatMap( matchResult -> Mono.just(this.obtainToken(request)))
				// 3、没有gets到，则抛出exception
				.switchIfEmpty(Mono.defer(() -> Mono.error(new AuthenticationJwtNotFoundException("Token not provided"))))
				// 4、构造 JwtAuthorizationToken
				.flatMap( token -> {
					JwtAuthorizationToken authRequest = new JwtAuthorizationToken(this.obtainUid(request), token);
					authRequest.setLongitude(this.obtainLongitude(request));
					authRequest.setLatitude(this.obtainLatitude(request));
					authRequest.setSign(this.obtainSign(request));
					return Mono.justOrEmpty(authRequest);
				})
				// 5、调用authentication接口，并构造 SecurityContext
				.flatMap( authRequest -> this.authenticationManager.authenticate(authRequest))
				.flatMap(authentication -> onAuthenticationSuccess(authentication, serverWebExchange));
	}
	
	/**
	 * on Authentication Success.
	 *
	 * @param authentication the authentication
	 * @param exchange the exchange
	 * @return the result
	 */
	protected Mono<SecurityContext> onAuthenticationSuccess(Authentication authentication, ServerWebExchange exchange) {
		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		return Mono.just(securityContext)
			.contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)))
			.cast(SecurityContext.class);
	}
	
	/**
	 * Returns the ant path matcher.
	 *
	 * @return the ant path matcher
	 */
	public AntPathMatcher getAntPathMatcher() {
		return antPathMatcher;
	}

	/**
	 * Sets the ant path matcher.
	 *
	 * @param antPathMatcher the ant path matcher
	 */
	public void setAntPathMatcher(AntPathMatcher antPathMatcher) {
		this.antPathMatcher = antPathMatcher;
	}

	/**
	 * Returns the white list.
	 *
	 * @return the white list
	 */
	public String[] getWhiteList() {
		return whiteList;
	}

	/**
	 * obtain Uid.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected String obtainUid(ServerHttpRequest request) {
		return request.getHeaders().getFirst(getUidHeaderName());
	}

	/**
	 * obtain Longitude.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected double obtainLongitude(ServerHttpRequest request) {
		return Double.parseDouble(StringUtils.defaultIfBlank(request.getHeaders().getFirst(getLongitudeHeaderName()), DEFAULT_LONGITUDE_LATITUDE));
	}
	
	/**
	 * obtain Latitude.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected double obtainLatitude(ServerHttpRequest request) {
		return Double.parseDouble(StringUtils.defaultIfBlank(request.getHeaders().getFirst(getLatitudeHeaderName()), DEFAULT_LONGITUDE_LATITUDE));
	}
	
	/**
	 * obtain Sign.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected String obtainSign(ServerHttpRequest request) {
		return request.getHeaders().getFirst(getSignHeaderName());
	}
	
	/**
	 * obtain Token.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected String obtainToken(ServerHttpRequest request) {
		// 从header中getstoken
		String token = request.getHeaders().getFirst(getAuthorizationHeaderName());
		// 如果header中不存在token，则从参数中getstoken
		if (StringUtils.isEmpty(token)) {
			return request.getQueryParams().getFirst(getAuthorizationParamName());
		}
		if (StringUtils.isEmpty(token)) {
			// 从 cookie gets token
			MultiValueMap<String, HttpCookie> cookies = request.getCookies();
			if (null == cookies || cookies.size() == 0) {
				return null;
			}
			HttpCookie cookie = request.getCookies().getFirst(getAuthorizationCookieName());
			if(!Objects.isNull(cookie)) {
				token = cookie.getValue();
			}
		}
		if (token == null) {
			token = "";
		}
		return token.trim();
	}

	/**
	 * Returns the authorization header name.
	 *
	 * @return the authorization header name
	 */
	public String getAuthorizationHeaderName() {
		return authorizationHeaderName;
	}

	/**
	 * Sets the authorization header name.
	 *
	 * @param authorizationHeaderName the authorization header name
	 */
	public void setAuthorizationHeaderName(String authorizationHeaderName) {
		this.authorizationHeaderName = authorizationHeaderName;
	}

	/**
	 * Returns the authorization param name.
	 *
	 * @return the authorization param name
	 */
	public String getAuthorizationParamName() {
		return authorizationParamName;
	}

	/**
	 * Sets the authorization param name.
	 *
	 * @param authorizationParamName the authorization param name
	 */
	public void setAuthorizationParamName(String authorizationParamName) {
		this.authorizationParamName = authorizationParamName;
	}

	/**
	 * Returns the authorization cookie name.
	 *
	 * @return the authorization cookie name
	 */
	public String getAuthorizationCookieName() {
		return authorizationCookieName;
	}

	/**
	 * Sets the authorization cookie name.
	 *
	 * @param authorizationCookieName the authorization cookie name
	 */
	public void setAuthorizationCookieName(String authorizationCookieName) {
		this.authorizationCookieName = authorizationCookieName;
	}

	/**
	 * Returns the uid header name.
	 *
	 * @return the uid header name
	 */
	public String getUidHeaderName() {
		return uidHeaderName;
	}

	/**
	 * Sets the uid header name.
	 *
	 * @param uidHeaderName the uid header name
	 */
	public void setUidHeaderName(String uidHeaderName) {
		this.uidHeaderName = uidHeaderName;
	}

	/**
	 * Returns the sign header name.
	 *
	 * @return the sign header name
	 */
	public String getSignHeaderName() {
		return signHeaderName;
	}

	/**
	 * Sets the sign header name.
	 *
	 * @param signHeaderName the sign header name
	 */
	public void setSignHeaderName(String signHeaderName) {
		this.signHeaderName = signHeaderName;
	}

	/**
	 * Returns the longitude header name.
	 *
	 * @return the longitude header name
	 */
	public String getLongitudeHeaderName() {
		return longitudeHeaderName;
	}

	/**
	 * Sets the longitude header name.
	 *
	 * @param longitudeHeaderName the longitude header name
	 */
	public void setLongitudeHeaderName(String longitudeHeaderName) {
		this.longitudeHeaderName = longitudeHeaderName;
	}

	/**
	 * Returns the latitude header name.
	 *
	 * @return the latitude header name
	 */
	public String getLatitudeHeaderName() {
		return latitudeHeaderName;
	}

	/**
	 * Sets the latitude header name.
	 *
	 * @param latitudeHeaderName the latitude header name
	 */
	public void setLatitudeHeaderName(String latitudeHeaderName) {
		this.latitudeHeaderName = latitudeHeaderName;
	}

	/**
	 * Returns the authentication manager.
	 *
	 * @return the authentication manager
	 */
	public ReactiveAuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}

	/**
	 * Sets the authentication manager.
	 *
	 * @param authenticationManager the authentication manager
	 */
	public void setAuthenticationManager(ReactiveAuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

}
