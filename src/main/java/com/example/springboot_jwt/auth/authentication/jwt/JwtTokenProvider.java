package com.example.springboot_jwt.auth.authentication.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtTokenProvider {
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final SecretKey signingKey;
    private final JwtProperties jwtProperties;

    public JwtTokenProvider(JwtProperties jwtProperties) {
        byte[] bytes = Base64.getDecoder().decode(jwtProperties.getSecretKey());
        this.signingKey = Keys.hmacShaKeyFor(bytes);
        this.jwtProperties = jwtProperties;
    }

    public String createAccessToken(Long userId, String email, String role) {
        Date date = new Date();
        return BEARER_PREFIX +
                Jwts.builder()
                        .subject(String.valueOf(userId))
                        .claim("email", email)
                        .claim("userRole", role)
                        .expiration(createExpiration(jwtProperties.getAccessTokenExpiration()))
                        .issuedAt(date)
                        .signWith(this.signingKey)
                        .compact();
    }

    private Date createExpiration(long tokenTime) {
        return new Date(System.currentTimeMillis() + tokenTime);
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(this.signingKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(this.signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String subStringToken(String tokenValue) {
        if (StringUtils.hasText(tokenValue) && tokenValue.startsWith(BEARER_PREFIX)) {
            return tokenValue.substring(BEARER_PREFIX.length());
        }
        throw new IllegalArgumentException("Invalid JWT");
    }

}
