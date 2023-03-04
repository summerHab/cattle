package com.cattle.auth.config;


import com.cattle.auth.ext.password.OAuth2PasswordAuthenticationConverter;
import com.cattle.auth.ext.password.OAuth2PasswordResourceAuthenticationProvider;
import com.cattle.auth.ext.password.OAuth2PasswordResourceAuthenticationProviderBuilder;
import com.cattle.auth.jose.Jwks;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import java.time.Duration;
import java.util.UUID;

/**
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();

		authorizationServerConfigurer
				.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
		RequestMatcher endpointsMatcher = authorizationServerConfigurer
				.getEndpointsMatcher();
		http.requestMatcher(endpointsMatcher)
			.authorizeHttpRequests(authorize ->
				authorize.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.exceptionHandling(exceptions ->
				exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
			)
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
			.apply(authorizationServerConfigurer.tokenEndpoint(

					tokenEndpoint->tokenEndpoint.accessTokenRequestConverter(new OAuth2PasswordAuthenticationConverter())
			));

		addCustomOAuth2GrantAuthenticationProvider(http);
		return http.build();
	}

	// @formatter:off
	@Bean
	public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("tiger")
				.clientSecret("{noop}tiger")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:20001/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:20001/authorized")
				.redirectUri("https://wwww.baidu.com")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PHONE)
				.scope("wx_app")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				// token配置项信息
				.tokenSettings(TokenSettings.builder()
						// token有效期100分钟
						.accessTokenTimeToLive(Duration.ofMinutes(100L))
						// 使用默认JWT相关格式
						.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
						// 开启刷新token
						.reuseRefreshTokens(true)
						// refreshToken有效期120分钟
						.refreshTokenTimeToLive(Duration.ofMinutes(120L))
						.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256).build()
				)
				.build();

//		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
//		registeredClientRepository.findByClientId("tiger");
		return new InMemoryRegisteredClientRepository(registeredClient);
	}
	// @formatter:on

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = Jwks.generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}


	/**
	 * 授权服务：管理OAuth2授权信息服务
	 */
	@Bean
	public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
	}

	/**
	 * 授权确认信息处理服务
	 */
	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
	}






	/**
	 * 注入授权模式实现提供方
	 *
	 * 1. 密码模式 </br>
	 * 2. 短信登录 </br>
	 *
	 */
	@SuppressWarnings("unchecked")
	private void addCustomOAuth2GrantAuthenticationProvider(HttpSecurity http) {

		OAuth2PasswordResourceAuthenticationProvider oAuth2PasswordResourceAuthenticationProvider = new OAuth2PasswordResourceAuthenticationProviderBuilder(
				http, userDetailsService, passwordEncoder).build();

		// 处理 UsernamePasswordAuthenticationToken
		http.authenticationProvider(oAuth2PasswordResourceAuthenticationProvider);
	}




}
