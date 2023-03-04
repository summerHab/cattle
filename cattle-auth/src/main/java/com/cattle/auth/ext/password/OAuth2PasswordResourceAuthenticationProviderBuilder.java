package com.cattle.auth.ext.password;


import com.cattle.auth.ext.utils.OAuth2ConfigurerUtils;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

public final class OAuth2PasswordResourceAuthenticationProviderBuilder {

    private HttpSecurity httpSecurity;
    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;

    public OAuth2PasswordResourceAuthenticationProviderBuilder(
            HttpSecurity httpSecurity, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.httpSecurity = httpSecurity;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }


    public OAuth2PasswordResourceAuthenticationProvider build() {
        OAuth2AuthorizationService authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);
        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity);
        OAuth2PasswordResourceAuthenticationProvider oAuth2PasswordResourceAuthenticationProvider =
                new OAuth2PasswordResourceAuthenticationProvider(authorizationService, tokenGenerator,
                        userDetailsService, passwordEncoder);
        return oAuth2PasswordResourceAuthenticationProvider;
    }

}
