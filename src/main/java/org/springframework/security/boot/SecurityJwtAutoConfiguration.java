package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthcOrAuthzFailureHandler;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.jwt.authentication.JwtMatchedAuthenticationSuccessHandler;

@Configuration
@ConditionalOnProperty(prefix = "security.jwt", name = "enabled", havingValue = "true", matchIfMissing = true)
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityJwtAuthcProperties.class })
public class SecurityJwtAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedAuthenticationEntryPoint jwtMatchedAuthenticationEntryPoint() {
		return new JwtMatchedAuthenticationEntryPoint();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedAuthcOrAuthzFailureHandler jwtMatchedAuthcOrAuthzFailureHandler() {
		return new JwtMatchedAuthcOrAuthzFailureHandler();
	}

	@Bean
	@ConditionalOnMissingBean
	public JwtMatchedAuthenticationSuccessHandler jwtMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new JwtMatchedAuthenticationSuccessHandler(payloadRepository);
	}

	@Bean
	@ConditionalOnMissingBean
	public JwtPayloadRepository payloadRepository() {
		return new JwtPayloadRepository() {};
	}

}
