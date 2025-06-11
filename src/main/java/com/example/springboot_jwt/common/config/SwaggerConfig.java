package com.example.springboot_jwt.common.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.servers.Server;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "SpringBoot_JWT",
                description = "Spring Boot 기반 JWT 인증/인가"
        ),
        servers = {
                @Server(url = "http://localhost:8080", description = "Local Server")
        }
)
@RequiredArgsConstructor
public class SwaggerConfig {
}
