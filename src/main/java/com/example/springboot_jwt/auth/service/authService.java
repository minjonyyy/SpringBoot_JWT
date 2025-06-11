package com.example.springboot_jwt.auth.service;

import com.example.springboot_jwt.auth.dto.SignUpRequest;
import com.example.springboot_jwt.auth.entity.User;
import com.example.springboot_jwt.auth.entity.UserRole;
import com.example.springboot_jwt.auth.repository.InMemoryAuthRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class authService {

    private final InMemoryAuthRepository repository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void signUp(SignUpRequest request) {
        // 중복 사용자 체크
        if (repository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("이미 존재하는 사용자입니다.");
        }
        String encodedPassword = bCryptPasswordEncoder.encode(request.getPassword());

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(encodedPassword)
                .role(UserRole.USER)
                .build();

        repository.save(user);
    }
}
