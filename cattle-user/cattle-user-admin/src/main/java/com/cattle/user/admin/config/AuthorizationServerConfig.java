package com.cattle.user.admin.config;




import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;




/**
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	@Bean
	@Order
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		http.sessionManagement().disable();
		http.authorizeRequests(
				authorizeRequests -> authorizeRequests.antMatchers("/oauth2/*").permitAll()// 开放自定义的部分端点
						.anyRequest().authenticated()
		).formLogin().and().csrf().disable().logout().and().oauth2ResourceServer().jwt();
		return http.build();
	}



}
