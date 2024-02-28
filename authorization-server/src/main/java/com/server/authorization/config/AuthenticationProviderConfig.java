package com.server.authorization.config;

import com.server.authorization.security.CustomJwtAuthenticationProvider;
import com.server.authorization.security.CustomPasswordGrantAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

@Configuration
public class AuthenticationProviderConfig {


  @Bean
  public CustomJwtAuthenticationProvider customJwtAuthenticationProvider(
      JwtDecoder jwtDecoder,
      UserDetailsService userDetailsService
  ) {
    return new CustomJwtAuthenticationProvider(jwtDecoder, userDetailsService);
  }

  @Bean
  public CustomPasswordGrantAuthenticationProvider customCodeGrantAuthenticationProvider(
      OAuth2TokenGenerator<OAuth2Token> jwtTokenGenerator,
      UserDetailsService userDetailsService,
      PasswordEncoder passwordEncoder
  ) {
    return new CustomPasswordGrantAuthenticationProvider(jwtTokenGenerator, userDetailsService, passwordEncoder);
  }
}
