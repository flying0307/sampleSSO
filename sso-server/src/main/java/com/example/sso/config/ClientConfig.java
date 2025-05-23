package com.example.sso.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "oauth2.client")
public class ClientConfig {
    
    private Map<String, ClientProperties> clients;

    public Map<String, ClientProperties> getClients() {
        return clients;
    }

    public void setClients(Map<String, ClientProperties> clients) {
        this.clients = clients;
    }

    public static class ClientProperties {
        private String clientId;
        private String clientSecret;
        private List<String> redirectUris;
        private List<String> scopes;
        private List<String> grantTypes;
        private boolean requireAuthorizationConsent = false;
        private int accessTokenValiditySeconds = 3600;
        private int refreshTokenValiditySeconds = 86400;

        // Getters and Setters
        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public List<String> getRedirectUris() {
            return redirectUris;
        }

        public void setRedirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }

        public List<String> getGrantTypes() {
            return grantTypes;
        }

        public void setGrantTypes(List<String> grantTypes) {
            this.grantTypes = grantTypes;
        }

        public boolean isRequireAuthorizationConsent() {
            return requireAuthorizationConsent;
        }

        public void setRequireAuthorizationConsent(boolean requireAuthorizationConsent) {
            this.requireAuthorizationConsent = requireAuthorizationConsent;
        }

        public int getAccessTokenValiditySeconds() {
            return accessTokenValiditySeconds;
        }

        public void setAccessTokenValiditySeconds(int accessTokenValiditySeconds) {
            this.accessTokenValiditySeconds = accessTokenValiditySeconds;
        }

        public int getRefreshTokenValiditySeconds() {
            return refreshTokenValiditySeconds;
        }

        public void setRefreshTokenValiditySeconds(int refreshTokenValiditySeconds) {
            this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
        }
    }
} 