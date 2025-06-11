package com.example.springboot_jwt.auth.entity;

import lombok.*;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class User {

    private Long id;
    private String username;
    private String email;
    private String password;
    private UserRole role;

}
