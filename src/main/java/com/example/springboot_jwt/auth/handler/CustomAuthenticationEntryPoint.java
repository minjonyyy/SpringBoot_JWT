package com.example.springboot_jwt.auth.handler;

import com.example.springboot_jwt.auth.exception.AuthErrorCode;
import com.example.springboot_jwt.common.exception.CommonErrorCode;
import com.example.springboot_jwt.common.exception.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        AuthErrorCode unauthorized = AuthErrorCode.UNAUTHORIZED;
        response.setStatus(unauthorized.getHttpStatus().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        ErrorResponse errorResponse = ErrorResponse.of(
                unauthorized
        );

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));

    }
}