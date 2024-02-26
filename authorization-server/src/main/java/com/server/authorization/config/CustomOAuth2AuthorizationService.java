package com.server.authorization.config;


import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

public class CustomOAuth2AuthorizationService implements OAuth2AuthorizationService {
  private final OAuth2AuthorizationService delegate;

  public CustomOAuth2AuthorizationService(OAuth2AuthorizationService delegate) {
    this.delegate = delegate;
  }

  @Override
  public void save(OAuth2Authorization authorization) {
    // 커스텀 로직을 여기에 추가
    System.out.printf("Saving authorization: %s", authorization);
    delegate.save(authorization);
    // accountService 해도 될듯?
  }

  @Override
  public void remove(OAuth2Authorization authorization) {
    // 커스텀 로직을 여기에 추가
    System.out.printf("Removing authorization: %s", authorization);
    delegate.remove(authorization);
  }

  @Override
  public OAuth2Authorization findById(String id) {
    // 필요한 경우 커스텀 로직을 추가
    return delegate.findById(id);
  }

  @Override
  public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
    // 필요한 경우 커스텀 로직을 추가
    return delegate.findByToken(token, tokenType);
  }
}