package com.server.authorization.security;

import java.time.Instant;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

@RequiredArgsConstructor
public class JwtRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

  private final JwtEncoder jwtEncoder;

  @Override
  public OAuth2RefreshToken generate(OAuth2TokenContext context) {
    Instant issuedAt = Instant.now();
    long ttl = context.getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive().getSeconds();
    Instant expiresAt = issuedAt.plusSeconds(ttl); // 예: 30일 후 만료

    // JWT 페이로드에 추가할 클레임 설정
    var claims = JwtClaimsSet.builder()
        .issuedAt(issuedAt)
        .expiresAt(expiresAt)
        .build();

    // JWT 생성
    Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));

    // 생성된 JWT를 사용하여 OAuth2RefreshToken 반환
    return new OAuth2RefreshToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt());
  }
}
