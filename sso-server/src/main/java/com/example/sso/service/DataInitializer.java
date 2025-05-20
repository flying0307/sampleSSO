package com.example.sso.service;

import com.example.sso.entity.User;
import com.example.sso.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        // 如果没有用户，则创建默认测试用户
        if (userRepository.count() == 0) {
            User adminUser = new User();
            adminUser.setUsername("admin");
            adminUser.setPassword(passwordEncoder.encode("password"));
            adminUser.setEmail("admin@example.com");
            adminUser.setAuthorities(Set.of("ROLE_ADMIN", "ROLE_USER"));
            
            User normalUser = new User();
            normalUser.setUsername("user");
            normalUser.setPassword(passwordEncoder.encode("password"));
            normalUser.setEmail("user@example.com");
            normalUser.setAuthorities(Set.of("ROLE_USER"));
            
            userRepository.saveAll(Set.of(adminUser, normalUser));
            
            System.out.println("Created default users: admin/password and user/password");
        }
    }
} 