package com.example.springboot_jwt.auth.authentication.filter;

import com.example.springboot_jwt.auth.authentication.jwt.JwtAuthenticationToken;
import com.example.springboot_jwt.auth.authentication.jwt.JwtTokenProvider;
import com.example.springboot_jwt.auth.entity.AuthUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.example.springboot_jwt.auth.authentication.jwt.JwtTokenProvider.*;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)) {
            String accessToken = jwtTokenProvider.subStringToken(authorizationHeader);

            try {
                Claims claims = jwtTokenProvider.extractClaims(accessToken);

                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    setAuthentication(claims);
                }
            } catch (SecurityException | MalformedJwtException e) {
                log.error("유효하지 않은 JWT 서명입니다.", e);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT signature");
                return;
            } catch (ExpiredJwtException e) {
                log.error("만료된 JWT 토큰입니다.", e);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
                return;
            } catch (UnsupportedJwtException e) {
                log.error("지원되지 않는 JWT 토큰입니다.", e);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unsupported JWT token");
                return;
            } catch (Exception e) {
                log.error("Internal server error", e);
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        }

        filterChain.doFilter(request, response);
    }

    private void setAuthentication(Claims claims) {
        Long userId = Long.valueOf(claims.getSubject());
        String email = claims.get("email", String.class);
        String userRole = claims.get("userRole", String.class);
        AuthUser authUser = AuthUser.builder()
                .id(userId)
                .email(email)
                .userRole(userRole)
                .build();
        JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(authUser);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }

}
