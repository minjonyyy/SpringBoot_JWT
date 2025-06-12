package com.example.springboot_jwt.auth.authentication.principal;

import com.example.springboot_jwt.auth.entity.UserRole;
import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
public class AuthUser {
    private Long id;
    private String email;
    private List<UserRole> userRoles;

    @Builder
    public AuthUser(Long id, String email, List<UserRole> userRoles) {
        this.id = id;
        this.email = email;
        this.userRoles = userRoles;
    }
}