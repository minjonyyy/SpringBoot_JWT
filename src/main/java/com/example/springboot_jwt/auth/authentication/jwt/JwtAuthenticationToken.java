package com.example.springboot_jwt.auth.authentication.jwt;

import com.example.springboot_jwt.auth.entity.AuthUser;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private final AuthUser authUser;

    public JwtAuthenticationToken(AuthUser authUser) {
        super(Collections.singleton(new SimpleGrantedAuthority(authUser.getUserRole())));
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
