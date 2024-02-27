package com.server.authorization.config;

import com.server.authorization.repository.JpaRegisteredClientRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

public class CustomCodeGrantAuthenticationProvider implements AuthenticationProvider {

  private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
  private final JpaRegisteredClientRepository registeredClientRepository;
  private final OAuth2AuthorizationService authorizationService;
  private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
  private final UserDetailsService userDetailsService;
  private final PasswordEncoder passwordEncoder;
  private String username = new String();
  private String password = new String();

  public CustomCodeGrantAuthenticationProvider(
      JpaRegisteredClientRepository registeredClientRepository,
      OAuth2AuthorizationService authorizationService,
      OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
      UserDetailsService userDetailsService,
      PasswordEncoder passwordEncoder
  ) {
    Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
    Assert.notNull(authorizationService, "authorizationService cannot be null");
    Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
    this.registeredClientRepository = registeredClientRepository;
    this.authorizationService = authorizationService;
    this.tokenGenerator = tokenGenerator;
    this.userDetailsService = userDetailsService;
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    CustomCodeGrantAuthenticationToken customCodeGrantAuthentication = (CustomCodeGrantAuthenticationToken) authentication;
    OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(customCodeGrantAuthentication);
    RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
    username = customCodeGrantAuthentication.getUsername();
    password = customCodeGrantAuthentication.getPassword();

    User user = null;
    try {
      user = (User) userDetailsService.loadUserByUsername(username);
    } catch (UsernameNotFoundException e) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
    }
    if (!passwordEncoder.matches(password, user.getPassword()) || !user.getUsername().equals(username)) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
    }
    if (!registeredClient.getAuthorizationGrantTypes().contains(customCodeGrantAuthentication.getGrantType())) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    }

    Authentication usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user, null,
        user.getAuthorities());

    DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
        .registeredClient(registeredClient)
        .principal(usernamePasswordAuthenticationToken)
        .authorizationServerContext(AuthorizationServerContextHolder.getContext())
        .authorizedScopes(registeredClient.getScopes())
        .authorizationGrantType(customCodeGrantAuthentication.getGrantType())
        .authorizationGrant(customCodeGrantAuthentication);

    // ----- Access Token -----
    OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
    OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
    if (generatedAccessToken == null) {
      OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
          "The token generator failed to generate the access token.", null);
      throw new OAuth2AuthenticationException(error);
    }
    OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
        generatedAccessToken.getExpiresAt(), null);

    OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
        .principalName(clientPrincipal.getName())
        .authorizationGrantType(customCodeGrantAuthentication.getGrantType());
    if (generatedAccessToken instanceof ClaimAccessor) {
      authorizationBuilder.token(accessToken,
          (metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
              ((ClaimAccessor) generatedAccessToken).getClaims()));
    } else {
      authorizationBuilder.accessToken(accessToken);
    }

    // ----- Refresh Token -----
    OAuth2RefreshToken refreshToken = null;
    if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
        && !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
      tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
      OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
      if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
        OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
            "The token generator failed to generate the refresh token.", ERROR_URI);
        throw new OAuth2AuthenticationException(error);
      }
      refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
      authorizationBuilder.refreshToken(refreshToken);
    }

    return new OAuth2AccessTokenAuthenticationToken(registeredClient, usernamePasswordAuthenticationToken, accessToken, refreshToken);
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return CustomCodeGrantAuthenticationToken.class.isAssignableFrom(authentication);
  }

  private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
      Authentication authentication) {
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