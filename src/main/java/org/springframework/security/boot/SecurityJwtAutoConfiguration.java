package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthenticationSuccessHandler;

/**
 * SecurityJwtAutoConfiguration.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Configuration
@AutoConfigureBefore(name = {
		"org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterAutoConfiguration"
})
/**
 * <p>Configuration properties.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class })
public class SecurityJwtAutoConfiguration {

	/**
	 * JWT Matched Authentication Entry Point.
	 *
	 * @return the result
	 */
	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedAuthenticationEntryPoint jwtMatchedAuthenticationEntryPoint() {
		return new JwtMatchedAuthenticationEntryPoint();
	}
	
	/**
	 * JWT Matched Authc Or Authz Failure Handler.
	 *
	 * @return the result
	 */
	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedAuthcOrAuthzFailureHandler jwtMatchedAuthcOrAuthzFailureHandler() {
		return new JwtMatchedAuthcOrAuthzFailureHandler();
	}

	/**
	 * JWT Matched Authentication Success Handler.
	 *
	 * @param payloadRepository the payload repository
	 * @return the result
	 */
	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedAuthenticationSuccessHandler jwtMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new JwtMatchedAuthenticationSuccessHandler(payloadRepository);
	}

	/**
	 * payload Repository.
	 *
	 * @return the result
	 */
	@Bean
	@ConditionalOnMissingBean
	public JwtPayloadRepository payloadRepository() {
		return new JwtPayloadRepository() {};
	}

}
