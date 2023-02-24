package com.cattle.auth.ext.password;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.util.StringUtils;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


@Slf4j
public class OAuth2PasswordAuthenticationProvider implements AuthenticationProvider {

    private PasswordEncoder passwordEncoder;

    private UserDetailsService userDetailsService;
    /***
     * 数据对比验证就在这里了
     * @param authentication
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication =
//                (OAuth2AuthorizationConsentAuthenticationToken) authentication;
//
//        OAuth2Authorization authorization = this.authorizationService.findByToken(
//                authorizationConsentAuthentication.getState(), STATE_TOKEN_TYPE);
//        if (authorization == null) {
//            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE,
//                    authorizationConsentAuthentication, null, null);
//        }
//
//        if (this.logger.isTraceEnabled()) {
//            this.logger.trace("Retrieved authorization with authorization consent state");
//        }
//
//        // The 'in-flight' authorization must be associated to the current principal
//        Authentication principal = (Authentication) authorizationConsentAuthentication.getPrincipal();
//        if (!isPrincipalAuthenticated(principal) || !principal.getName().equals(authorization.getPrincipalName())) {
//            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE,
//                    authorizationConsentAuthentication, null, null);
//        }
//
//        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
//                authorizationConsentAuthentication.getClientId());
//        if (registeredClient == null || !registeredClient.getId().equals(authorization.getRegisteredClientId())) {
//            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
//                    authorizationConsentAuthentication, registeredClient, null);
//        }
//
//        if (log.isTraceEnabled()) {
//            log.trace("Retrieved registered client");
//        }
//
//        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
//        Set<String> requestedScopes = authorizationRequest.getScopes();
//        Set<String> authorizedScopes = new HashSet<>(authorizationConsentAuthentication.getScopes());
//        if (!requestedScopes.containsAll(authorizedScopes)) {
//            throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE,
//                    authorizationConsentAuthentication, registeredClient, authorizationRequest);
//        }
//
//        if (log.isTraceEnabled()) {
//            log.trace("Validated authorization consent request parameters");
//        }
//
//        OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
//                authorization.getRegisteredClientId(), authorization.getPrincipalName());
//        Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null ?
//                currentAuthorizationConsent.getScopes() : Collections.emptySet();
//
//        if (!currentAuthorizedScopes.isEmpty()) {
//            for (String requestedScope : requestedScopes) {
//                if (currentAuthorizedScopes.contains(requestedScope)) {
//                    authorizedScopes.add(requestedScope);
//                }
//            }
//        }
//
//        if (!authorizedScopes.isEmpty() && requestedScopes.contains(OidcScopes.OPENID)) {
//            // 'openid' scope is auto-approved as it does not require consent
//            authorizedScopes.add(OidcScopes.OPENID);
//        }
//
//        OAuth2AuthorizationConsent.Builder authorizationConsentBuilder;
//        if (currentAuthorizationConsent != null) {
//            if (this.logger.isTraceEnabled()) {
//                this.logger.trace("Retrieved existing authorization consent");
//            }
//            authorizationConsentBuilder = OAuth2AuthorizationConsent.from(currentAuthorizationConsent);
//        } else {
//            authorizationConsentBuilder = OAuth2AuthorizationConsent.withId(
//                    authorization.getRegisteredClientId(), authorization.getPrincipalName());
//        }
//        authorizedScopes.forEach(authorizationConsentBuilder::scope);
//
//        if (this.authorizationConsentCustomizer != null) {
//            // @formatter:off
//            OAuth2AuthorizationConsentAuthenticationContext authorizationConsentAuthenticationContext =
//                    OAuth2AuthorizationConsentAuthenticationContext.with(authorizationConsentAuthentication)
//                            .authorizationConsent(authorizationConsentBuilder)
//                            .registeredClient(registeredClient)
//                            .authorization(authorization)
//                            .authorizationRequest(authorizationRequest)
//                            .build();
//            // @formatter:on
//            this.authorizationConsentCustomizer.accept(authorizationConsentAuthenticationContext);
//            if (this.logger.isTraceEnabled()) {
//                this.logger.trace("Customized authorization consent");
//            }
//        }
//
//        Set<GrantedAuthority> authorities = new HashSet<>();
//        authorizationConsentBuilder.authorities(authorities::addAll);
//
//        if (authorities.isEmpty()) {
//            // Authorization consent denied (or revoked)
//            if (currentAuthorizationConsent != null) {
//                this.authorizationConsentService.remove(currentAuthorizationConsent);
//                if (this.logger.isTraceEnabled()) {
//                    this.logger.trace("Revoked authorization consent");
//                }
//            }
//            this.authorizationService.remove(authorization);
//            if (this.logger.isTraceEnabled()) {
//                this.logger.trace("Removed authorization");
//            }
//            throwError(OAuth2ErrorCodes.ACCESS_DENIED, OAuth2ParameterNames.CLIENT_ID,
//                    authorizationConsentAuthentication, registeredClient, authorizationRequest);
//        }
//
//        OAuth2AuthorizationConsent authorizationConsent = authorizationConsentBuilder.build();
//        if (!authorizationConsent.equals(currentAuthorizationConsent)) {
//            this.authorizationConsentService.save(authorizationConsent);
//            if (this.logger.isTraceEnabled()) {
//                this.logger.trace("Saved authorization consent");
//            }
//        }
//
//        OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(
//                authorizationConsentAuthentication, registeredClient, authorization, authorizedScopes);
//        OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
//        if (authorizationCode == null) {
//            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
//                    "The token generator failed to generate the authorization code.", ERROR_URI);
//            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
//        }
//
//        if (this.logger.isTraceEnabled()) {
//            this.logger.trace("Generated authorization code");
//        }
//
//        OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
//                .authorizedScopes(authorizedScopes)
//                .token(authorizationCode)
//                .attributes(attrs -> {
//                    attrs.remove(OAuth2ParameterNames.STATE);
//                })
//                .build();
//        this.authorizationService.save(updatedAuthorization);
//
//        if (this.logger.isTraceEnabled()) {
//            this.logger.trace("Saved authorization");
//        }
//
//        String redirectUri = authorizationRequest.getRedirectUri();
//        if (!StringUtils.hasText(redirectUri)) {
//            redirectUri = registeredClient.getRedirectUris().iterator().next();
//        }
//
//        if (this.logger.isTraceEnabled()) {
//            this.logger.trace("Authenticated authorization consent request");
//        }
//
//        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
//                authorizationRequest.getAuthorizationUri(), registeredClient.getClientId(), principal, authorizationCode,
//                redirectUri, authorizationRequest.getState(), authorizedScopes);
        return null;
    }




    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordAuthenticationProvider.class.isAssignableFrom(authentication);
    }
}
