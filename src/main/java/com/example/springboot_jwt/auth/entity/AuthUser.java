package com.example.springboot_jwt.auth.entity;

import lombok.Builder;
import lombok.Getter;

@Getter
public class AuthUser {
    private Long id;
    private String email;
    private String userRole;

    @Builder
    private AuthUser(Long id, String email, String userRole) {
        this.id = id;
        this.email = email;
        this.userRole = userRole;
    }
}