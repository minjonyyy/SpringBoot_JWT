package com.example.springboot_jwt.auth.authentication.filter;

import com.example.springboot_jwt.auth.authentication.jwt.JwtAuthenticationToken;
import com.example.springboot_jwt.auth.authentication.jwt.JwtTokenProvider;
import com.example.springboot_jwt.auth.authentication.principal.AuthUser;
import com.example.springboot_jwt.auth.entity.UserRole;
import com.example.springboot_jwt.auth.exception.AuthErrorCode;
import com.example.springboot_jwt.common.exception.CustomException;
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
import java.util.List;

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
                log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.", e);
                throw new CustomException(AuthErrorCode.INVALID_JWT_SIGNATURE);

            } catch (ExpiredJwtException e) {
                log.error("Expired JWT token, 만료된 JWT token 입니다.", e);
                throw new CustomException(AuthErrorCode.TOKEN_EXPIRED);
            } catch (UnsupportedJwtException e) {
                log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.", e);
                throw new CustomException(AuthErrorCode.UNSUPPORTED_TOKEN);
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

        List<String> rolesByString = claims.get("roles", List.class);
        List<UserRole> userRoles = rolesByString.stream().map(UserRole::of).toList();

        AuthUser authUser = AuthUser.builder()
                .id(userId)
                .email(email)
                .userRoles(userRoles)
                .build();
        JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(authUser);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }

}
