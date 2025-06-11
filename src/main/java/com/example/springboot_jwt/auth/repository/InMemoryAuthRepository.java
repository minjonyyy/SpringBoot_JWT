package com.example.springboot_jwt.auth.repository;

import com.example.springboot_jwt.auth.entity.User;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

@Repository
public class InMemoryAuthRepository {

    private final Map<String, User> storage = new HashMap<>();
    private final AtomicLong idGenerator = new AtomicLong(1);

    public void save(User user) {
        Long id = idGenerator.getAndIncrement();

        User userWithId = User.builder()
                .id(id)
                .username(user.getUsername())
                .email(user.getEmail())
                .password(user.getPassword())
                .role(user.getRole())
                .build();

        storage.put(userWithId.getEmail(), userWithId);
    }

    public Optional<User> findByEmail(String email) {
        return Optional.ofNullable(storage.get(email));
    }
}
