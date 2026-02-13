package com.dbiswa.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthencationFilter extends OncePerRequestFilter {
    private final JwtService JwtService;
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        final String authencationHeader = request.getHeader("Authorization");
        final String jwtToken;
        final String userEmail;
        if(authencationHeader == null || !authencationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwtToken = authencationHeader.substring(7);
        userEmail = JwtService.extractUsername(jwtToken);//extract userEmail

    }
}
