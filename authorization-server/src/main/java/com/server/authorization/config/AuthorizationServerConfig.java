package com.server.authorization.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.server.authorization.repository.JpaRegisteredClientRepository;
import com.server.authorization.service.JwtCustomizer;
import com.server.authorization.service.MemberService;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.UUID;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AuthorizationServerConfig {

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(
      HttpSecurity http,
      JwtEncoder jwtEncoder,
      JpaRegisteredClientRepository registeredClientRepository,
      MemberService memberService,
      JwtCustomizer jwtCustomizer
  ) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .registeredClientRepository(registeredClientRepository)
        .tokenEndpoint(tokenEndpoint -> tokenEndpoint
            .accessTokenRequestConverter(new CustomCodeGrantAuthenticationConverter())
            .authenticationProvider(new CustomCodeGrantAuthenticationProvider(
                registeredClientRepository,
                oAuth2AuthorizationService(),
                tokenGenerator(jwtEncoder, jwtCustomizer),
                memberService,
                passwordEncoder()))
        );

    http
        // Accept access tokens for User Info and/or Client Registration
        .oauth2ResourceServer(resourceServer -> resourceServer
            .jwt(Customizer.withDefaults()));

    return http.build();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository(JpaRegisteredClientRepository jpaRegisteredClientRepository) {
    // 클라이언트 정보를 등록하는 객체를 만든다.
//    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//        .clientId("clientid")
//        .clientSecret("{noop}secret")
//        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // password 방식으로 custom 이 필요함.
//        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//        .authorizationGrantType(new AuthorizationGrantType("password"))
//        .redirectUri("http://127.0.0.1:8081")
//        .scope("store")
//        .scope("order")
//        .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofSeconds(31536000)).build())
//        .build();
//
//    jpaRegisteredClientRepository.save(registeredClient);

    return jpaRegisteredClientRepository;
  }

  @Bean
  UserDetailsService userDetailsService(MemberService userService) {
    return userService;
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException, InvalidKeySpecException {
    final String publicKey = ""; /* private key */
    final String privateKey = ""; /* public key */

    KeyFactory kf = KeyFactory.getInstance("RSA");

    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(privateKeySpec);

    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
    RSAPublicKey rsaPublicKey = (RSAPublicKey) kf.generatePublic(publicKeySpec);

    RSAKey rsaKey = new RSAKey.Builder(rsaPublicKey)
        .privateKey(rsaPrivateKey)
        .build();
    JWKSet jwkSet = new JWKSet(rsaKey);

    return new ImmutableJWKSet<>(jwkSet);
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
    return new NimbusJwtEncoder(jwkSource);
  }

  @Bean
  OAuth2AuthorizationService oAuth2AuthorizationService() {
    return new InMemoryOAuth2AuthorizationService();
  }

  @Bean
  public OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder, JwtCustomizer jwtCustomizer) {
    CustomJwtGenerator customJwtGenerator = new CustomJwtGenerator(jwtEncoder);
    customJwtGenerator.setJwtCustomizer(jwtCustomizer);
    OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
    OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

    return new DelegatingOAuth2TokenGenerator(
        customJwtGenerator, accessTokenGenerator, refreshTokenGenerator
    );
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }
}
