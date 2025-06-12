package com.example.springboot_jwt.auth.controller;

import com.example.springboot_jwt.auth.dto.request.LogInRequest;
import com.example.springboot_jwt.auth.dto.request.SignUpRequest;
import com.example.springboot_jwt.auth.dto.response.SignUpResponse;
import com.example.springboot_jwt.auth.dto.response.TokenResponse;
import com.example.springboot_jwt.auth.dto.response.UserRoleResponse;
import com.example.springboot_jwt.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Parameter;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/auth/signup")
    public ResponseEntity<SignUpResponse> signUp(@Valid @RequestBody SignUpRequest request) {
        SignUpResponse response = authService.signUp(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/auth/login")
    public ResponseEntity<TokenResponse> logIn(@Valid @RequestBody LogInRequest request) {
        TokenResponse accessToken = authService.logIn(request);
        return ResponseEntity.ok(accessToken);
    }

    @PatchMapping("/admin/users/{userId}/roles")
    @Secured("ADMIN")
    public ResponseEntity<UserRoleResponse> grantAdminRole(
            @Parameter(description = "Admin 권한을 부여할 사용자 Id", required = true)
            @PathVariable Long userId
    ) {
        UserRoleResponse response = authService.grantAdminRole(userId);
        return ResponseEntity.ok(response);
    }
}
