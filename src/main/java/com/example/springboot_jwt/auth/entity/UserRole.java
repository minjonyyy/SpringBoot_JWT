package com.example.springboot_jwt.auth.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;

@Getter
@RequiredArgsConstructor
public enum UserRole {
    ROLE_USER(Authority.USER, "user"),
    ROLE_ADMIN(Authority.ADMIN, "admin"),
    ;

    private final String userRole;
    private final String stateValue;

    public static UserRole of(String role) {
        return Arrays.stream(UserRole.values())
                .filter(r -> r.name().equalsIgnoreCase(role))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid user role: " + role));
    }

    public static UserRole fromState(String state) {
        return Arrays.stream(values())
                .filter(r -> r.stateValue.equalsIgnoreCase(state))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid user state: " + state));
    }

    public static class Authority {
        public static final String USER = "ROLE_USER";
        public static final String ADMIN = "ROLE_ADMIN";
    }

}