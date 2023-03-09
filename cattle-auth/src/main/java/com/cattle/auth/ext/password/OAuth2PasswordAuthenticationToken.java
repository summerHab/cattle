package com.cattle.auth.ext.password;


import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.Map;

public final class OAuth2PasswordAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
    private final AuthorizationGrantType authorizationGrantType;
    private final Authentication clientPrincipal;
    private final Map<String, Object> additionalParameters;
    private final String username;
    private final String password;


    protected OAuth2PasswordAuthenticationToken(AuthorizationGrantType authorizationGrantType,
                                                Authentication clientPrincipal,
                                                Map<String, Object> additionalParameters,
                                                String username,
                                                String password
    ) {
        super(Collections.emptyList());
        Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        this.username = username;
        this.password = password;
        this.authorizationGrantType = authorizationGrantType;
        this.clientPrincipal = clientPrincipal;
        this.additionalParameters = additionalParameters;
    }


    public AuthorizationGrantType getAuthorizationGrantType() {
        return authorizationGrantType;
    }

    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }//用户名称

    @Override
    public Object getCredentials() {
        return "";
    }//用户密码 扩展模式一般不用

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }


    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
