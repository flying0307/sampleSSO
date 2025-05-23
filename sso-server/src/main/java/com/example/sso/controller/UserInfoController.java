package com.example.sso.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

@RestController
public class UserInfoController {
    
    private static final Logger logger = Logger.getLogger(UserInfoController.class.getName());

    @GetMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> getUserInfo(@AuthenticationPrincipal Jwt jwt) {
        logger.info("处理UserInfo请求, JWT Subject: " + (jwt != null ? jwt.getSubject() : "null"));
        
        if (jwt == null) {
            return ResponseEntity.badRequest().build();
        }
        
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("sub", jwt.getSubject());
        
        // 添加标准OIDC字段
        if (jwt.hasClaim("name")) {
            userInfo.put("name", jwt.getClaim("name"));
        }
        
        if (jwt.hasClaim("email")) {
            userInfo.put("email", jwt.getClaim("email"));
        } else {
            // 提供一个基于subject的默认邮箱
            userInfo.put("email", jwt.getSubject() + "@example.com");
        }
        
        // 添加用户角色/权限
        if (jwt.hasClaim("authorities")) {
            userInfo.put("authorities", jwt.getClaim("authorities"));
        }
        
        userInfo.put("preferred_username", jwt.getSubject());
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        
        return ResponseEntity
                .ok()
                .headers(headers)
                .body(userInfo);
    }
} 