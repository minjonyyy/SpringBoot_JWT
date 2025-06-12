package com.example.springboot_jwt.auth.controller;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@SpringBootTest
@ExtendWith(SpringExtension.class)
class AuthControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "user@test.com", roles = "USER")
    void 일반사용자가_관리자권한부여요청시_403에러발생() throws Exception {
        // given
        Long userId = 1L;

        // when & then
        mockMvc.perform(patch("/admin/users/{userId}/roles", userId))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin@test.com", roles = "ADMIN")
    void 관리자가_관리자권한부여요청시_성공() throws Exception {
        Long userId = 1L;

        mockMvc.perform(patch("/admin/users/{userId}/roles", userId))
                .andExpect(status().isOk());
    }
}