package com.example.springboot_jwt.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

@Getter
@Schema(description = "토큰 응답 dto")
public class TokenResponse {
    @Schema(description = "발급된 액세스 토큰", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    private final String accessToken;

    public TokenResponse(String accessToken) {
        this.accessToken = accessToken;
    }

    public static TokenResponse of(String accessToken) {
        return new TokenResponse(accessToken);
    }
}
