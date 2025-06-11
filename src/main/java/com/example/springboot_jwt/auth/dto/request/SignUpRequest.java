package com.example.springboot_jwt.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;

@Getter
@Schema(description = "사용자 회원가입 요청")
public class SignUpRequest {

    @NotBlank(message = "사용자명은 필수 입력 항목입니다.")
    @Schema(description = "사용자명", example = "username")
    private String username;

    @NotBlank(message = "이메일은 필수 입력 항목입니다.")
    @Email(message = "유효한 이메일 주소 형식이어야 합니다.")
    @Schema(description = "사용자 이메일", example = "user@example.com")
    private String email;

    @NotBlank(message = "비밀번호는 필수 입력 항목입니다.")
    @Pattern(regexp = "^(?=.*[A-Z])(?=.*[0-9])(?=.*[a-z])(?=.*[!@#$%^&]).{8,}$"
            , message = "대문자, 숫자, 특수문자(!,@,#,$,%,^,&)를 최소 1개 이상 포함한 8자리 이상으로 입력해주세요.")
    @Schema(description = "비밀번호", example = "Password123!")
    private String password;

}
