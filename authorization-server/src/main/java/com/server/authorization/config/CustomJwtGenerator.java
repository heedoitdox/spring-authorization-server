package com.server.authorization.config;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;
import org.springframework.lang.Nullable;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
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
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

@Component
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
    if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
      // TODO Allow configuration for ID Token time-to-live
      expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES);
      if (registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm() != null) {
        jwsAlgorithm = registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm();
      }
    } else {
      expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());
    }

    // @formatter:off
    JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
    if (StringUtils.hasText(issuer)) {
      claimsBuilder.issuer(issuer);
    }
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
    } else if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
      claimsBuilder.claim(IdTokenClaimNames.AZP, registeredClient.getClientId());
      if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())) {
        OAuth2AuthorizationRequest authorizationRequest = context.getAuthorization().getAttribute(
            OAuth2AuthorizationRequest.class.getName());
        String nonce = (String) authorizationRequest.getAdditionalParameters().get(OidcParameterNames.NONCE);
        if (StringUtils.hasText(nonce)) {
          claimsBuilder.claim(IdTokenClaimNames.NONCE, nonce);
        }
        SessionInformation sessionInformation = context.get(SessionInformation.class);
        if (sessionInformation != null) {
          claimsBuilder.claim("sid", sessionInformation.getSessionId());
          claimsBuilder.claim(IdTokenClaimNames.AUTH_TIME, sessionInformation.getLastRequest());
        }
      } else if (AuthorizationGrantType.REFRESH_TOKEN.equals(context.getAuthorizationGrantType())) {
        OidcIdToken currentIdToken = context.getAuthorization().getToken(OidcIdToken.class).getToken();
        if (currentIdToken.hasClaim("sid")) {
          claimsBuilder.claim("sid", currentIdToken.getClaim("sid"));
        }
        if (currentIdToken.hasClaim(IdTokenClaimNames.AUTH_TIME)) {
          claimsBuilder.claim(IdTokenClaimNames.AUTH_TIME, currentIdToken.<Date>getClaim(IdTokenClaimNames.AUTH_TIME));
        }
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

    /* custom header, claims 등록 */
    JwsHeader jwsHeader = jwsHeaderBuilder.header("typ", "JWT").build();
    JwtClaimsSet claims = claimsBuilder
        .claim("custom-claims", "")
        .build();

    Jwt jwt = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

    return jwt;
  }
}
