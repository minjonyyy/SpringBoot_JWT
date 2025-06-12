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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;

@ExtendWith(SpringExtension.class)
public class AuthServiceTest {

    @InjectMocks
    private AuthService authService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    private static SignUpRequest createSignupUserRequest(String username, String email, String password) {
        return SignUpRequest.builder()
                .username(username)
                .email(email)
                .password(password)
                .build();
    }

    @Nested
    class SignUpTest {

        @Test
        void 회원가입_성공() {
            // given
            String username = "test";
            String email = "test@test.com";
            String password = "password";
            SignUpRequest request = createSignupUserRequest(username, email, password);

            given(userRepository.findByEmail(request.getEmail())).willReturn(Optional.empty());
            given(passwordEncoder.encode(request.getPassword())).willReturn("encoded-password");

            // when
            SignUpResponse response = authService.signUp(request);

            // then
            assertThat(response.getUsername()).isEqualTo(username);
            assertThat(response.getRoles()).containsExactlyInAnyOrder(UserRole.ROLE_USER);
        }

        @Test
        void 회원가입_실패_중복_이메일_DUPLICATED_EMAIL_예외_발생() {
            // given
            String username = "test";
            String email = "test@test.com";
            String password = "password";
            SignUpRequest request = createSignupUserRequest(username, email, password);

            given(userRepository.findByEmail(request.getEmail()))
                    .willReturn(Optional.of(User.builder().build()));

            // when & then
            assertThatThrownBy(() -> authService.signUp(request)).isInstanceOf(CustomException.class)
                    .hasMessage(AuthErrorCode.DUPLICATED_EMAIL.getMessage());

        }

    }

    @Nested
    class LoginTest {

        @Test
        void 로그인_성공() {
            // given
            String email = "test@test.com";
            String rawPassword = "password";
            String encodedPassword = "encoded-password";
            String accessToken = "fake-token";

            LogInRequest request = LogInRequest.builder()
                    .email(email)
                    .password(rawPassword)
                    .build();

            User user = User.builder()
                    .id(1L)
                    .email(email)
                    .password(encodedPassword)
                    .roles(Set.of(UserRole.ROLE_USER))
                    .build();

            given(userRepository.findByEmail(email)).willReturn(Optional.of(user));
            given(passwordEncoder.matches(rawPassword, encodedPassword)).willReturn(true);
            given(jwtTokenProvider.createAccessToken(user.getId(), email, user.getRoles())).willReturn(accessToken);

            // when
            TokenResponse response = authService.logIn(request);

            // then
            assertThat(response.getAccessToken()).isEqualTo(accessToken);
        }

        @Test
        void 로그인_실패_존재하지않는_이메일_EMAIL_NOT_FOUND_예외_발생() {
            // given
            LogInRequest request = LogInRequest.builder()
                    .email("no@email.com")
                    .password("pass")
                    .build();

            given(userRepository.findByEmail(request.getEmail())).willReturn(Optional.empty());

            // when & then
            assertThatThrownBy(() -> authService.logIn(request))
                    .isInstanceOf(CustomException.class)
                    .hasMessage(UserErrorCode.EMAIL_NOT_FOUND.getMessage());
        }

        @Test
        void 로그인_실패_비밀번호불일치_INVALID_PASSWORD() {
            // given
            String email = "test@test.com";
            String rawPassword = "wrong-password";
            String encodedPassword = "encoded-password";

            User user = User.builder()
                    .id(1L)
                    .email(email)
                    .password(encodedPassword)
                    .roles(Set.of(UserRole.ROLE_USER))
                    .build();

            LogInRequest request = LogInRequest.builder()
                    .email(email)
                    .password(rawPassword)
                    .build();

            given(userRepository.findByEmail(email)).willReturn(Optional.of(user));
            given(passwordEncoder.matches(rawPassword, encodedPassword)).willReturn(false);

            // when & then
            assertThatThrownBy(() -> authService.logIn(request))
                    .isInstanceOf(CustomException.class)
                    .hasMessage(UserErrorCode.INVALID_PASSWORD.getMessage());
        }
    }


    @Nested
    class GrantAdminRoleTest {

        @Test
        void 관리자권한_부여_성공() {
            // given
            Long userId = 1L;
            User user = User.builder()
                    .id(userId)
                    .email("admin@test.com")
                    .roles(new HashSet<>(Set.of(UserRole.ROLE_USER)))
                    .build();

            given(userRepository.findById(userId)).willReturn(Optional.of(user));

            // when
            UserRoleResponse response = authService.grantAdminRole(userId);

            // then
            assertThat(response.getRoles()).contains(UserRole.ROLE_ADMIN);
        }

        @Test
        void 관리자권한_부여_실패_사용자없음_USER_NOT_FOUND_예외_발생() {
            // given
            Long userId = 999L;

            given(userRepository.findById(userId)).willReturn(Optional.empty());

            // when & then
            assertThatThrownBy(() -> authService.grantAdminRole(userId))
                    .isInstanceOf(CustomException.class)
                    .hasMessage(UserErrorCode.USER_NOT_FOUND.getMessage());
        }
    }

}
