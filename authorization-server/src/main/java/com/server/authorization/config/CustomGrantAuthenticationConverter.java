package com.server.authorization.config;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * grant type 을 커스텀 한 클래스
 */
@Component
public class CustomGrantAuthenticationConverter implements AuthenticationConverter {

  @Nullable
  @Override
  public Authentication convert(HttpServletRequest request) {

    String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
    Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

    return switch (grantType) {
      case "password", "refresh_token" -> {
        final Map<String, Object> additionalParameters = extractAdditionalParameters(request);
        yield new PasswordAuthenticationToken(grantType, clientPrincipal, additionalParameters);
      }
      case "custom_credentials" -> {
        final Map<String, Object> additionalParameters = extractAdditionalParameters(request);
        yield new CustomCredentialsAuthenticationToken(grantType, clientPrincipal, additionalParameters);
      }
      default ->
        throw new OAuth2AuthenticationException(
            new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Bad credentials", ""),
            "invalid grant_type :" + grantType
        );
    };
  }

  /**
   * 추가 매개변수 추출 메서드
   *
   * @param request
   * @return
   */
  private Map<String, Object> extractAdditionalParameters(HttpServletRequest request) {
    MultiValueMap<String, String> parameters = getParameters(request);
    Map<String, Object> additionalParameters = new HashMap<>();
    parameters.forEach((key, value) -> {
      if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
          !key.equals(OAuth2ParameterNames.CLIENT_ID)
      ) {
        additionalParameters.put(key, value.get(0));
      }
    });
    return additionalParameters;
  }

  private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
    Map<String, String[]> parameterMap = request.getParameterMap();
    MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
    parameterMap.forEach((key, values) -> {
      if (values.length > 0) {
        for (String value : values) {
          parameters.add(key, value);
        }
      }
    });
    return parameters;
  }
}