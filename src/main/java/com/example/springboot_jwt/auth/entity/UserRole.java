package com.example.springboot_jwt.auth.entity;

import com.example.springboot_jwt.auth.exception.UserErrorCode;
import com.example.springboot_jwt.common.exception.CustomException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.Arrays;

@Getter
@RequiredArgsConstructor
public enum UserRole implements GrantedAuthority {
    ROLE_USER(Authority.USER, "user"),
    ROLE_ADMIN(Authority.ADMIN, "admin"),
    ;

    private final String userRole;
    private final String stateValue;

    public static UserRole of(String role) {
        return Arrays.stream(UserRole.values())
                .filter(r -> r.name().equalsIgnoreCase(role))
                .findFirst()
                .orElseThrow(() -> new CustomException(UserErrorCode.INVALID_USER_ROLE));
    }

    public static class Authority {
        public static final String USER = "ROLE_USER";
        public static final String ADMIN = "ROLE_ADMIN";
    }

    @Override
    public String getAuthority() {
        return name();
    }

}