package com.server.authorization.config;

import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

public class PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
  private final String username;
  private final String password;

  protected PasswordAuthenticationToken(
      String grantType,
      Authentication clientPrincipal,
      Map<String, Object> additionalParameters) {
    super(new AuthorizationGrantType(grantType), clientPrincipal, additionalParameters);
    this.username = (String) additionalParameters.get(OAuth2ParameterNames.USERNAME);
    this.password = (String) additionalParameters.get(OAuth2ParameterNames.PASSWORD);
  }

  public String getUsername() {
    return this.username;
  }

  public String getPassword() {
    return this.password;
  }

}
