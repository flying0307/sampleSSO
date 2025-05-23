package com.example.sso.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class OidcDiscoveryController {

    @Value("${server.port:8080}")
    private int port;

    @GetMapping(path = "/.well-known/openid-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> discoveryConfiguration() {
        String issuer = "http://localhost:" + port;
        Map<String, Object> config = new HashMap<>();
        
        config.put("issuer", issuer);
        config.put("authorization_endpoint", issuer + "/oauth2/authorize");
        config.put("token_endpoint", issuer + "/oauth2/token");
        config.put("jwks_uri", issuer + "/oauth2/jwks");
        config.put("userinfo_endpoint", issuer + "/userinfo");
        config.put("response_types_supported", List.of("code"));
        config.put("subject_types_supported", List.of("public"));
        config.put("id_token_signing_alg_values_supported", List.of("RS256"));
        config.put("scopes_supported", List.of("openid", "profile", "email"));
        config.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post"));
        config.put("claims_supported", List.of("sub", "name", "preferred_username", "email"));
        
        return config;
    }
} 