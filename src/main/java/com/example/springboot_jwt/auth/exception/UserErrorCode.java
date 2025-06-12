package com.example.springboot_jwt.auth.exception;

import com.example.springboot_jwt.common.exception.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum UserErrorCode implements ErrorCode {

    // 400 Bad Request
    EMAIL_NOT_FOUND(HttpStatus.BAD_REQUEST, "USER_001", "존재하지 않는 이메일입니다."),
    INVALID_USER_ROLE(HttpStatus.BAD_REQUEST, "USER_003", "유효하지 않은 Role 입니다."),
    INVALID_USER_ROLE_STATE(HttpStatus.BAD_REQUEST,"USER_004","유효하지 않은 사용자 권한 정보입니다."),
    INVALID_PASSWORD(HttpStatus.UNAUTHORIZED, "USER_005", "비밀번호가 일치하지 않습니다."),


    // 404 Not Found
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "USER_002", "유저를 찾을 수 없습니다."),
    ;

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;


}