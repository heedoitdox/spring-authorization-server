package com.server.authorization.service;

import com.server.authorization.entity.MemberEntity;
import com.server.authorization.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService implements UserDetailsService {

  private final MemberRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) {
    final MemberEntity user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException(""));

    return User.builder()
        .username(user.getUsername())
        .password(user.getPassword())
        .build();
  }
}
