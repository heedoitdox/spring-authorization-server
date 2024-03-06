package com.server.authorization.security;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class CustomAuthorizationGrantType {
  public static final AuthorizationGrantType CUSTOM_PASSWORD = new AuthorizationGrantType("custom_password");


}
