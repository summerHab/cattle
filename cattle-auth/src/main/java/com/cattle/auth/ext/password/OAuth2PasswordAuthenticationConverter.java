package com.cattle.auth.ext.password;


import com.auth.common.core.constant.AuthorizationConstants;
import com.cattle.auth.ext.util.OAuth2EndpointUtils;
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



public final class OAuth2PasswordAuthenticationConverter implements AuthenticationConverter {



    @Override
    public Authentication convert(HttpServletRequest request) {

        // grant_type (REQUIRED) sms_code
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationConstants.AUTHORIZATION_GRANT_TYPE_SMS_CODE.equals(grantType)) {
            return null;
        }
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);
        // scope (OPTIONAL)
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope) &&
                parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.SCOPE,
                   OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        Set<String> requestedScopes = null;
        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(
                    Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        //参数校验
        this.checkParams(request);

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.SCOPE)) {
                additionalParameters.put(key, value.get(0));
            }
        });
        return new OAuth2PasswordAuthenticationToken(
                AuthorizationGrantType.PASSWORD,
                clientPrincipal, requestedScopes, additionalParameters);
    }


    /***
     * 参数校验
     * @param request
     */
    public void checkParams(HttpServletRequest request) {
        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);
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
    }


}
