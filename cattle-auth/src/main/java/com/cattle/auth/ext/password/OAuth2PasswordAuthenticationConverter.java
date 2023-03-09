package com.cattle.auth.ext.password;


import com.cattle.auth.ext.utils.OAuth2EndpointUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.*;


/***
 * @author byh
 * @descreation oauth2 扩展的password  AuthenticationConverter
 * @date 2023-03-02
 */

public final class OAuth2PasswordAuthenticationConverter implements AuthenticationConverter {


    @Override
    public Authentication convert(HttpServletRequest request) {
        // grant_type (REQUIRED) password
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
            return null;
        }
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

        //参数校验
        // username (REQUIRED)
        String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
        if (!StringUtils.hasText(username) || parameters.get(OAuth2ParameterNames.USERNAME).size() != 1) {
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.USERNAME,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        // password (REQUIRED)
        String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
        if (!StringUtils.hasText(password) || parameters.get(OAuth2ParameterNames.PASSWORD).size() != 1) {
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.PASSWORD,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE)) {
                additionalParameters.put(key, value.get(0));
            }
        });
        return new OAuth2PasswordAuthenticationToken(
                AuthorizationGrantType.PASSWORD,
                clientPrincipal, additionalParameters, username, password);
    }


}
