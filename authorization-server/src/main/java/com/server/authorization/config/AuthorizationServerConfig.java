package com.server.authorization.config;

import com.server.authorization.security.CustomJwtAuthenticationProvider;
import com.server.authorization.security.CustomPasswordGrantAuthenticationConverter;
import com.server.authorization.security.CustomPasswordGrantAuthenticationProvider;
import java.time.Duration;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AuthorizationServerConfig {

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(
      HttpSecurity http,
      OAuth2TokenGenerator<OAuth2Token> jwtTokenGenerator,
      CustomJwtAuthenticationProvider customJwtAuthenticationProvider,
      CustomPasswordGrantAuthenticationProvider customPasswordGrantAuthenticationProvider
  ) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .tokenEndpoint(tokenEndpoint ->
                tokenEndpoint
                        .accessTokenRequestConverter(new CustomPasswordGrantAuthenticationConverter())
                        .authenticationProvider(customJwtAuthenticationProvider)
                        .authenticationProvider(customPasswordGrantAuthenticationProvider))
        .tokenGenerator(jwtTokenGenerator);

//    http
//        // Accept access tokens for User Info and/or Client Registration
//        .oauth2ResourceServer(resourceServer -> resourceServer
//            .jwt(Customizer.withDefaults()));

    return http.build();
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("authorization-client")
        .clientSecret("{noop}authorization-client-secret")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofSeconds(31560000))
            .refreshTokenTimeToLive(Duration.ofSeconds(31560000))
            .reuseRefreshTokens(true)
            .build())
        .clientSettings(ClientSettings.builder()
            .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
            .build())
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .authorizationGrantType(CustomAuthorizationGrantType.CUSTOM_PASSWORD)
        .scope("read")
        .build();

    return new InMemoryRegisteredClientRepository(registeredClient);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

}
