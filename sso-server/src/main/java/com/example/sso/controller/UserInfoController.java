package com.example.sso.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
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

    @GetMapping(path = "/userinfo", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getUserInfo(@AuthenticationPrincipal Jwt jwt) {
        logger.info("处理UserInfo请求");
        
        if (jwt == null) {
            logger.warning("JWT为空，可能是认证问题");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        logger.info("JWT信息: " + jwt.getSubject());
        
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
        
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(userInfo);
    }
} 