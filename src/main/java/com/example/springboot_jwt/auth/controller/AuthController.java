package com.example.springboot_jwt.auth.controller;

import com.example.springboot_jwt.auth.dto.request.LogInRequest;
import com.example.springboot_jwt.auth.dto.request.SignUpRequest;
import com.example.springboot_jwt.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<String> signUp(@Valid @RequestBody SignUpRequest request) {
        authService.signUp(request);
        return ResponseEntity.ok("회원가입 성공");
    }

    @PostMapping("/login")
    public ResponseEntity<String> logIn(@Valid @RequestBody LogInRequest request) {
        authService.logIn(request);
        return ResponseEntity.ok("로그인 성공");
    }
}
