package com.server.authorization.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TokenPathRewriteFilter extends OncePerRequestFilter {

    @Value("${oauth2.token.endpoint}")
    private String tokenEndpoint;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestURI = request.getRequestURI();

        List<String> tokenPaths = List.of("/oauth3/token", "/test/token");
        // 조건에 따라 경로 변경 로직 구현
        for (String path: tokenPaths) {
            if (requestURI.startsWith(path)) {
                // 실제 서버에서 /a 경로의 처리를 /b 경로로 재작성하고자 할 때 로직 구현
                String newRequestURI = requestURI.replace(path, tokenEndpoint);
                // 요청을 새 경로로 전달
                request.getRequestDispatcher(newRequestURI).forward(request, response);
                return;
            }
        }

        // 다른 경로에 대한 요청은 변경 없이 그대로 진행
        filterChain.doFilter(request, response);
    }
}
