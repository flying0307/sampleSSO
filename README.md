# Spring Boot 3 单点登录 (SSO) 系统

本项目是一个基于Spring Boot 3和Spring Security实现的完整单点登录(SSO)解决方案，包含授权服务器和客户端应用。

## 系统架构

项目由以下两个主要组件组成：

1. **sso-server** - OAuth2/OIDC授权服务器
   - 基于Spring Authorization Server实现
   - 提供OAuth2和OpenID Connect协议支持
   - 包含用户认证、授权和令牌管理功能

2. **sso-client** - OAuth2客户端应用
   - 使用Spring OAuth2 Client实现
   - 通过授权码流程与授权服务器交互
   - 展示用户登录后的受保护资源

## 技术栈

- Java 17+
- Spring Boot 3.1.5
- Spring Security 6
- Spring Authorization Server
- Spring OAuth2 Client
- Thymeleaf模板引擎
- H2内存数据库
- JWT令牌

## 关键功能

- **OAuth2授权码流程** - 标准的OAuth2认证流程
- **OpenID Connect** - 在OAuth2基础上提供用户身份信息
- **JWT令牌** - 使用JWT格式的访问令牌
- **用户信息端点** - 提供用户属性的REST API
- **CORS支持** - 允许跨域资源共享
- **状态管理** - 防止CSRF攻击
- **会话管理** - 使用JDBC实现会话持久化

## 启动步骤

### 启动授权服务器

```bash
cd sso-server
./mvnw spring-boot:run
```

授权服务器将在 http://localhost:8080 启动

### 启动客户端应用

```bash
cd sso-client
./mvnw spring-boot:run
```

客户端应用将在 http://localhost:8081 启动

## 测试账户

系统预置了两个测试用户：

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin  | password | ROLE_ADMIN, ROLE_USER |
| user   | password | ROLE_USER |

## 流程演示

1. 访问客户端应用 http://localhost:8081
2. 点击"使用SSO登录"按钮
3. 系统重定向到授权服务器的登录页面
4. 使用上述任一账户登录
5. 授权服务器会请求用户确认是否授权客户端访问所请求的权限
6. 确认后，用户被重定向回客户端应用
7. 客户端应用展示用户信息和JWT令牌详情

## 关键配置说明

### 授权服务器

- **AuthorizationServerConfig** - 配置OAuth2授权服务器核心功能
- **ResourceServerConfig** - 处理用户信息端点的资源服务器配置
- **UserInfoController** - 提供用户属性的REST API
- **OidcDiscoveryController** - OpenID Connect发现端点

### 客户端应用

- **SecurityConfig** - OAuth2客户端安全配置
- **application.yml** - 配置OAuth2提供方和客户端注册信息

## 系统扩展方向

- 添加更多OAuth2授权模式支持
- 实现用户注册流程
- 添加多租户支持
- 集成外部身份提供商
- 实现令牌撤销和刷新
- 增强安全特性（如多因素认证）

## 注意事项

- 当前实现使用内存数据库，生产环境应考虑使用持久化存储
- 测试环境使用HTTP，生产环境应配置HTTPS
- 默认用户信息仅用于演示，生产环境应替换 