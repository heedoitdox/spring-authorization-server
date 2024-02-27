package com.server.authorization.config;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;
import org.springframework.lang.Nullable;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

public class CustomJwtGenerator implements OAuth2TokenGenerator<Jwt> {
  private final JwtEncoder jwtEncoder;
  private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

  /**
   * Constructs a {@code JwtGenerator} using the provided parameters.
   *
   * @param jwtEncoder the jwt encoder
   */
  public CustomJwtGenerator(JwtEncoder jwtEncoder) {
    Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
    this.jwtEncoder = jwtEncoder;
  }

  @Nullable
  @Override
  public Jwt generate(OAuth2TokenContext context) {
    if (context.getTokenType() == null ||
        (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) &&
            !OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue()))) {
      return null;
    }
    if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) &&
        !OAuth2TokenFormat.SELF_CONTAINED.equals(context.getRegisteredClient().getTokenSettings().getAccessTokenFormat())) {
      return null;
    }

    String issuer = null;
    if (context.getAuthorizationServerContext() != null) {
      issuer = context.getAuthorizationServerContext().getIssuer();
    }
    RegisteredClient registeredClient = context.getRegisteredClient();

    Instant issuedAt = Instant.now();
    Instant expiresAt;
    JwsAlgorithm jwsAlgorithm = SignatureAlgorithm.RS256;
    expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());

    JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();

    claimsBuilder
        .subject(context.getPrincipal().getName())
            /* contains 시킬 resourceId 등록 그래야 인가됨 */
        .audience(Collections.unmodifiableList(Arrays.asList("", "")))
        .issuedAt(issuedAt)
        .expiresAt(expiresAt)
        .id(UUID.randomUUID().toString());
    if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
      claimsBuilder.notBefore(issuedAt);
      if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
        claimsBuilder.claim(OAuth2ParameterNames.SCOPE, context.getAuthorizedScopes());
      }
    }
    // @formatter:on

    JwsHeader.Builder jwsHeaderBuilder = JwsHeader.with(jwsAlgorithm);;

    if (this.jwtCustomizer != null) {
      // @formatter:off
      JwtEncodingContext.Builder jwtContextBuilder = JwtEncodingContext.with(jwsHeaderBuilder, claimsBuilder)
          .registeredClient(context.getRegisteredClient())
          .principal(context.getPrincipal())
          .authorizationServerContext(context.getAuthorizationServerContext())
          .authorizedScopes(context.getAuthorizedScopes())
          .tokenType(context.getTokenType())
          .authorizationGrantType(context.getAuthorizationGrantType());
      if (context.getAuthorization() != null) {
        jwtContextBuilder.authorization(context.getAuthorization());
      }
      if (context.getAuthorizationGrant() != null) {
        jwtContextBuilder.authorizationGrant(context.getAuthorizationGrant());
      }
      if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
        SessionInformation sessionInformation = context.get(SessionInformation.class);
        if (sessionInformation != null) {
          jwtContextBuilder.put(SessionInformation.class, sessionInformation);
        }
      }
      // @formatter:on

      JwtEncodingContext jwtContext = jwtContextBuilder.build();
      this.jwtCustomizer.customize(jwtContext);
    }

    JwsHeader jwsHeader = jwsHeaderBuilder.build();
    JwtClaimsSet claims = claimsBuilder.build();

    Jwt jwt = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

    return jwt;
  }

  public void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
    Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
    this.jwtCustomizer = jwtCustomizer;
  }
}
