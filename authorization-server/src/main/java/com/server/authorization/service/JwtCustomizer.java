package com.server.authorization.service;

import com.server.authorization.entity.PhoneEntity;
import com.server.authorization.repository.PhoneRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

/**
 * 만들어진 JWT 토큰에서 클레임이나 헤더를 추가하는 등 커스터마이징 하는 클래스
 */
@Component
@RequiredArgsConstructor
public class JwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

  private final PhoneRepository phoneRepository;

  @Override
  public void customize(JwtEncodingContext context) {
    if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
      // 유저 정보 가져와서 토큰 클레임에 추가하기
      // context 에 유저객체를 포함하기는 어려워 보인다. CustomJwtGenerator 에서도 이미 인증된 유저객체를 갖고 있진 않는 것으로 보임
      // 따라서 여기서 한번더 조회해와야 할 수도 있다.
      final PhoneEntity phone = phoneRepository.findByMemberId(1L).orElse(null);

      // 토큰 클레임에 넣고 싶은 정보들을 추가.
      context.getClaims()
          .claim("phone", phone.getPhone());

      // 이전 스펙과 같게 하기위해 넣음 (없을시 리소스 서버에서 인가 불가)
      context.getJwsHeader().header("typ", "JWT");
    }

    // TODO: refresh token
  }
}
