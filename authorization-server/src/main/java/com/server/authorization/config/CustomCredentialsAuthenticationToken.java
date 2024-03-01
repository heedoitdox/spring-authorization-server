package com.server.authorization.config;

import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

public class CustomCredentialsAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
  private final String customCode;

  protected CustomCredentialsAuthenticationToken(
      String grantType,
      Authentication clientPrincipal,
      Map<String, Object> additionalParameters
  ) {
    super(new AuthorizationGrantType(grantType), clientPrincipal, additionalParameters);
    this.customCode = (String) additionalParameters.get("custom_code");
  }

  public String getCustomCode() {
    return this.customCode;
  }
}
