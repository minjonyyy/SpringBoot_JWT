package com.example.springboot_jwt.auth.service;

import com.example.springboot_jwt.auth.dto.request.LogInRequest;
import com.example.springboot_jwt.auth.dto.request.SignUpRequest;
import com.example.springboot_jwt.auth.entity.User;
import com.example.springboot_jwt.auth.entity.UserRole;
import com.example.springboot_jwt.auth.repository.InMemoryAuthRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final InMemoryAuthRepository repository;
    private final BCryptPasswordEncoder passwordEncoder;

    public void signUp(SignUpRequest request) {
        // 중복 사용자 체크
        if (repository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("이미 존재하는 사용자입니다.");
        }

        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(encodedPassword)
                .role(UserRole.USER) // default Role : USER
                .build();

        repository.save(user);
    }

    public void logIn(LogInRequest request) {
        User user = repository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }
    }


}
