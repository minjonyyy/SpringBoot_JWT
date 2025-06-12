package com.example.springboot_jwt.auth.service;

import com.example.springboot_jwt.auth.authentication.jwt.JwtTokenProvider;
import com.example.springboot_jwt.auth.dto.request.LogInRequest;
import com.example.springboot_jwt.auth.dto.request.SignUpRequest;
import com.example.springboot_jwt.auth.dto.response.SignUpResponse;
import com.example.springboot_jwt.auth.dto.response.TokenResponse;
import com.example.springboot_jwt.auth.dto.response.UserRoleResponse;
import com.example.springboot_jwt.auth.entity.User;
import com.example.springboot_jwt.auth.entity.UserRole;
import com.example.springboot_jwt.auth.exception.AuthErrorCode;
import com.example.springboot_jwt.auth.exception.UserErrorCode;
import com.example.springboot_jwt.auth.repository.UserRepository;
import com.example.springboot_jwt.common.exception.CustomException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public SignUpResponse signUp(SignUpRequest request) {
        // 중복 사용자 체크
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new CustomException(AuthErrorCode.DUPLICATED_EMAIL);
        }

        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(encodedPassword)
                .roles(Set.of(UserRole.ROLE_USER))
                .createdAt(LocalDateTime.now())
                .build();

        userRepository.save(user);

        return SignUpResponse.toDto(user);
    }

    public TokenResponse logIn(LogInRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new CustomException(UserErrorCode.EMAIL_NOT_FOUND));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new CustomException(UserErrorCode.INVALID_PASSWORD);
        }

        String accessToken = jwtTokenProvider.createAccessToken(user.getId(), user.getEmail(), user.getRoles());

        return TokenResponse.of(accessToken);
    }

    @Transactional
    public UserRoleResponse grantAdminRole(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(UserErrorCode.USER_NOT_FOUND));

        user.getRoles().add(UserRole.ROLE_ADMIN);

        return UserRoleResponse.toDto(user);
    }
}
