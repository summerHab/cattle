package com.cattle.auth.ext.password;


import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class OAuth2PasswordAuthenticationToken extends AbstractAuthenticationToken {


    private final AuthorizationGrantType authorizationGrantType;

    private final Authentication clientPrincipal;

    private final Map<String, Object> additionalParameters;

    private final Set<String> scopes;


    /**
     * Sub-class constructor.
     * @param authorizationGrantType the authorization grant type
     * @param clientPrincipal        用户信息
     * @param additionalParameters   扩展的参数携带map
     */
    protected OAuth2PasswordAuthenticationToken(AuthorizationGrantType authorizationGrantType, Authentication clientPrincipal, Set<String> scopes, Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        this.authorizationGrantType = authorizationGrantType;
        this.clientPrincipal = clientPrincipal;
        this.scopes = scopes;//暂时没有使用
        this.additionalParameters = additionalParameters;
    }


    /**
     * Returns the authorization grant type.
     * @return the authorization grant type
     */
    public AuthorizationGrantType getGrantType() {
        return this.authorizationGrantType;
    }

    /***
     * 获取用户名
     * @return
     */
    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }

    /***
     * 扩展模式不需要密码
     * @return
     */
    @Override
    public Object getCredentials() {
        return "";
    }


    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
