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
        for (String path: tokenPaths) {
            if (requestURI.startsWith(path)) {
                String newRequestURI = requestURI.replace(path, tokenEndpoint);
                request.getRequestDispatcher(newRequestURI).forward(request, response);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
