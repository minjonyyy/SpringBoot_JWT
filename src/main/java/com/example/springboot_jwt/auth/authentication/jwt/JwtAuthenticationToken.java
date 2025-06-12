package com.example.springboot_jwt.auth.authentication.jwt;

import com.example.springboot_jwt.auth.authentication.principal.AuthUser;
import com.example.springboot_jwt.auth.entity.UserRole;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.stream.Collectors;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private final AuthUser authUser;

    public JwtAuthenticationToken(AuthUser authUser) {
        super(authUser.getUserRoles().stream()
                .map(UserRole::getAuthority)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList()));
        this.authUser = authUser;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return authUser;
    }
}
