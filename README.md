# Spring Boot 3 單點登錄 (SSO) 系統

本項目是一個基於Spring Boot 3和Spring Security實現的完整單點登錄(SSO)解決方案，包含授權服務器和客戶端應用。

## 系統架構

項目由以下兩個主要組件組成：

1. **sso-server** - OAuth2/OIDC授權服務器
   - 基於Spring Authorization Server實現
   - 提供OAuth2和OpenID Connect協議支持
   - 包含用戶認證、授權和令牌管理功能

2. **sso-client** - OAuth2客戶端應用
   - 使用Spring OAuth2 Client實現
   - 通過授權碼流程與授權服務器交互
   - 展示用戶登錄後的受保護資源

## 技術棧

- Java 17+
- Spring Boot 3.1.5
- Spring Security 6
- Spring Authorization Server
- Spring OAuth2 Client
- Thymeleaf模板引擎
- H2內存數據庫
- JWT令牌

## 詳細調用流程

### 1. 初始化階段

1. **客戶端應用啓動**
   - 客戶端應用（端口8081）啓動時，會向授權服務器（端口8080）請求OpenID Connect配置
   - 請求URL: `GET http://localhost:8080/.well-known/openid-configuration`
   - 獲取授權端點、令牌端點、用戶信息端點等配置信息

2. **授權服務器啓動**
   - 初始化OAuth2授權服務器配置
   - 創建默認用戶（admin/password, user/password）
   - 配置JWT簽名密鑰
   - 設置客戶端註冊信息

### 2. 認證流程

1. **用戶訪問客戶端**
   - 用戶訪問 `http://localhost:8081`
   - 客戶端檢測到未認證狀態，重定向到授權服務器

2. **授權請求**
   - 客戶端重定向到授權端點：`http://localhost:8080/oauth2/authorize`
   - 請求參數包含：
     - `response_type=code`
     - `client_id=sample-client`
     - `redirect_uri=http://localhost:8081/login/oauth2/code/sso-client`
     - `scope=openid profile`
     - `state=[隨機狀態值]`

3. **用戶登錄**
   - 用戶被重定向到登錄頁面：`http://localhost:8080/login`
   - 輸入用戶名和密碼
   - 服務器驗證憑據並創建會話

4. **授權確認**
   - 用戶確認授權請求
   - 授權服務器生成授權碼
   - 重定向回客戶端，URL包含授權碼：`http://localhost:8081/login/oauth2/code/sso-client?code=[授權碼]&state=[狀態值]`

### 3. 令牌獲取

1. **客戶端請求令牌**
   - 客戶端使用授權碼請求訪問令牌
   - 請求URL: `POST http://localhost:8080/oauth2/token`
   - 請求頭包含：
     - `Authorization: Basic [client_id:client_secret的Base64編碼]`
   - 請求體包含：
     - `grant_type=authorization_code`
     - `code=[授權碼]`
     - `redirect_uri=http://localhost:8081/login/oauth2/code/sso-client`

2. **令牌響應**
   - 授權服務器驗證請求
   - 生成JWT格式的訪問令牌
   - 返回響應：
     ```json
     {
       "access_token": "[JWT令牌]",
       "token_type": "Bearer",
       "expires_in": 3600,
       "scope": "openid profile"
     }
     ```

### 4. 資源訪問

1. **訪問用戶信息**
   - 客戶端使用訪問令牌請求用戶信息
   - 請求URL: `GET http://localhost:8080/userinfo`
   - 請求頭包含：
     - `Authorization: Bearer [訪問令牌]`

2. **用戶信息響應**
   - 授權服務器驗證令牌
   - 返回用戶信息：
     ```json
     {
       "sub": "[用戶ID]",
       "name": "[用戶名]",
       "email": "[郵箱]",
       "authorities": ["ROLE_USER"]
     }
     ```

### 5. 令牌刷新

1. **刷新令牌請求**
   - 當訪問令牌過期時，客戶端可以使用刷新令牌獲取新的訪問令牌
   - 請求URL: `POST http://localhost:8080/oauth2/token`
   - 請求體包含：
     - `grant_type=refresh_token`
     - `refresh_token=[刷新令牌]`

2. **新令牌響應**
   - 授權服務器驗證刷新令牌
   - 生成新的訪問令牌和刷新令牌
   - 返回響應：
     ```json
     {
       "access_token": "[新的JWT令牌]",
       "refresh_token": "[新的刷新令牌]",
       "token_type": "Bearer",
       "expires_in": 3600
     }
     ```

## 關鍵功能

- **OAuth2授權碼流程** - 標準的OAuth2認證流程
- **OpenID Connect** - 在OAuth2基礎上提供用戶身份信息
- **JWT令牌** - 使用JWT格式的訪問令牌
- **用戶信息端點** - 提供用戶屬性的REST API
- **CORS支持** - 允許跨域資源共享
- **狀態管理** - 防止CSRF攻擊
- **會話管理** - 使用JDBC實現會話持久化

## 啓動步驟

### 啓動授權服務器

```bash
cd sso-server
./mvnw spring-boot:run
```

授權服務器將在 http://localhost:8080 啓動

### 啓動客戶端應用

```bash
cd sso-client
./mvnw spring-boot:run
```

客戶端應用將在 http://localhost:8081 啓動

## 測試賬戶

系統預置了兩個測試用戶：

| 用戶名 | 密碼 | 角色 |
|--------|------|------|
| admin  | password | ROLE_ADMIN, ROLE_USER |
| user   | password | ROLE_USER |

## 流程演示

1. 訪問客戶端應用 http://localhost:8081
2. 點擊"使用SSO登錄"按鈕
3. 系統重定向到授權服務器的登錄頁面
4. 使用上述任一賬戶登錄
5. 授權服務器會請求用戶確認是否授權客戶端訪問所請求的權限
6. 確認後，用戶被重定向回客戶端應用
7. 客戶端應用展示用戶信息和JWT令牌詳情

## 關鍵配置說明

### 授權服務器

- **AuthorizationServerConfig** - 配置OAuth2授權服務器核心功能
- **ResourceServerConfig** - 處理用戶信息端點的資源服務器配置
- **UserInfoController** - 提供用戶屬性的REST API
- **OidcDiscoveryController** - OpenID Connect發現端點

### 客戶端應用

- **SecurityConfig** - OAuth2客戶端安全配置
- **application.yml** - 配置OAuth2提供方和客戶端註冊信息

## 系統擴展方向

- 添加更多OAuth2授權模式支持
- 實現用戶註冊流程
- 添加多租戶支持
- 集成外部身份提供商
- 實現令牌撤銷和刷新
- 增強安全特性（如多因素認證）

## 注意事項

- 當前實現使用內存數據庫，生產環境應考慮使用持久化存儲
- 測試環境使用HTTP，生產環境應配置HTTPS
- 默認用戶信息僅用於演示，生產環境應替換 