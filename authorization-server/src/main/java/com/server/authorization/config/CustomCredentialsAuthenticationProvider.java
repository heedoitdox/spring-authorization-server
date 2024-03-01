package com.server.authorization.config;

import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomCredentialsAuthenticationProvider implements AuthenticationProvider {

  private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    CustomCredentialsAuthenticationToken customAuthenticationToken = (CustomCredentialsAuthenticationToken) authentication;
    OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClient(customAuthenticationToken);
    RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

    final String customCode = customAuthenticationToken.getCustomCode();
    // TODO: customCode 조회 및 검증

    if (!registeredClient.getAuthorizationGrantTypes().contains(customAuthenticationToken.getGrantType())) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    }

    DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
        .registeredClient(registeredClient)
        .principal(customAuthenticationToken)
        .authorizationServerContext(AuthorizationServerContextHolder.getContext())
        .authorizedScopes(registeredClient.getScopes())
        .authorizationGrantType(customAuthenticationToken.getGrantType())
        .authorizationGrant(customAuthenticationToken);

    // access_token 생성
    OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
    OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
    if (generatedAccessToken == null) {
      OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
          "The token generator failed to generate the access token.", null);
      throw new OAuth2AuthenticationException(error);
    }

    OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
        generatedAccessToken.getExpiresAt(), registeredClient.getScopes().stream().collect(Collectors.toSet()));

//    OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
//        .principalName(clientPrincipal.getName())
//        .authorizationGrantType(customAuthenticationToken.getGrantType());
//    if (generatedAccessToken instanceof ClaimAccessor) {
//      authorizationBuilder.token(accessToken,
//          (metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
//              ((ClaimAccessor) generatedAccessToken).getClaims()));
//    } else {
//      authorizationBuilder.accessToken(accessToken);
//    }

    final Map<String, Object> scopes = Map.of("scope", registeredClient.getScopes().stream().collect(Collectors.joining(" ")));
    return new OAuth2AccessTokenAuthenticationToken(registeredClient, customAuthenticationToken, accessToken, null, scopes);
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return CustomCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
  }

  private static OAuth2ClientAuthenticationToken getAuthenticatedClient(Authentication authentication) {
    OAuth2ClientAuthenticationToken clientPrincipal = null;
    if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
      clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
    }
    if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
      return clientPrincipal;
    }
    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
  }
}
