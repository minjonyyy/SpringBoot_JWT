package com.example.springboot_jwt.auth.dto.response;

import com.example.springboot_jwt.auth.entity.User;
import com.example.springboot_jwt.auth.entity.UserRole;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Set;

@Getter
@Schema(description = "Admin 권한 부여 성공 응답")
@RequiredArgsConstructor
@Builder
public class UserRoleResponse {

    private final String username;
    private final Set<UserRole> roles;

    public static UserRoleResponse toDto(User user) {
        return UserRoleResponse.builder()
                .username(user.getUsername())
                .roles(user.getRoles())
                .build();
    }

}
