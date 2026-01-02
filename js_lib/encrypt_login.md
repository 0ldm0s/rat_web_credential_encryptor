# 加密登录工具使用文档

## 概述

`encrypt_login.cjs` 是一个用于生成加密登录/注册数据的命令行工具。它使用 AES-256-GCM 算法对用户名、密码等敏感信息进行加密，确保在网络传输过程中不暴露明文凭据。

## 依赖

- Node.js
- crypto 模块（Node.js 内置）

## 使用方法

### 获取会话密钥

首先需要从 SSO 服务获取会话密钥（session_id）和加密密钥（key）：

```bash
curl -X POST http://localhost:31005/api/v1/auth/get-key
```

响应示例：
```json
{
  "code": 200,
  "msg": "OK",
  "data": {
    "session_id": "d1bc1ab8-3a3b-43ec-b7ed-9f4f26476387",
    "key": "lzgFNttqn8BJjtaJmQ/sYOzm6xRwnEyIc2IVf73+Snw=",
    "expires_in": 300
  }
}
```

> **注意**：会话密钥有效期为 5 分钟（300 秒），过期后需要重新获取。

### 登录模式

用于生成加密的登录凭据：

```bash
node encrypt_login.cjs <key_base64> <username> <password> [session_id]
```

**参数说明：**
- `key_base64`：从 `/api/v1/auth/get-key` 获取的 Base64 编码密钥
- `username`：用户名
- `password`：密码
- `session_id`（可选）：会话 ID，不提供则自动生成

**示例：**
```bash
node encrypt_login.cjs "lzgFNttqn8BJjtaJmQ/sYOzm6xRwnEyIc2IVf73+Snw=" "admin" "admin123"
```

输出示例：
```json
{
  "session_id": "d1bc1ab8-3a3b-43ec-b7ed-9f4f26476387",
  "encrypted_username": "ri4IhrQ5L07zK85O4nBl7jLl7hknbU8x7suUc905rnjIKo3gwhE=",
  "encrypted_password": "ri4IhrQ5L07zK85O5nU17vr6p96Bz1/Cu4uoONk9rn/KNpr2wxDa"
}

curl -X POST http://localhost:31005/api/v1/auth/secure-login -H "Content-Type: application/json" -d '{"session_id":"d1bc1ab8-3a3b-43ec-b7ed-9f4f26476387","encrypted_username":"ri4IhrQ5L07zK85O4nBl7jLl7hknbU8x7suUc905rnjIKo3gwhE=","encrypted_password":"ri4IhrQ5L07zK85O5nU17vr6p96Bz1/Cu4uoONk9rn/KNpr2wxDa"}'
```

### 注册模式

用于生成加密的注册凭据：

```bash
node encrypt_login.cjs --register <key_base64> <username> <email> <password> <password_confirm> [session_id]
```

**参数说明：**
- `key_base64`：从 `/api/v1/auth/get-key` 获取的 Base64 编码密钥
- `username`：用户名
- `email`：邮箱地址
- `password`：密码
- `password_confirm`：确认密码
- `session_id`（可选）：会话 ID，不提供则自动生成

**示例：**
```bash
node encrypt_login.cjs --register "lzgFNttqn8BJjtaJmQ/sYOzm6xRwnEyIc2IVf73+Snw=" "newuser" "user@example.com" "password123" "password123"
```

输出示例：
```json
{
  "session_id": "d1bc1ab8-3a3b-43ec-b7ed-9f4f26476387",
  "encrypted_username": "ri4IhrQ5L07zK85O4nBl7jLl7hknbU8x7suUc905rnjIKo3gwhE=",
  "encrypted_email": "ri4IhrQ5L07zK85ONFn5hd6UsvN6fj+3nocfBd05rniNaqj3ikOE8T5H5qSGlQ==",
  "encrypted_password": "ri4IhrQ5L07zK85O5nU17vr6p96Bz1/Cu4uoONk9rn/KNpr2wxDa",
  "encrypted_password_confirm": "ri4IhrQ5L07zK85O5nU17vr6p96Bz1/Cu4uoONk9rn/KNpr2wxDa"
}

curl -X POST http://localhost:31005/api/v1/auth/secure-register -H "Content-Type: application/json" -d '{"session_id":"d1bc1ab8-3a3b-43ec-b7ed-9f4f26476387","encrypted_username":"ri4IhrQ5L07zK85O4nBl7jLl7hknbU8x7suUc905rnjIKo3gwhE=","encrypted_email":"ri4IhrQ5L07zK85ONFn5hd6UsvN6fj+3nocfBd05rniNaqj3ikOE8T5H5qSGlQ==","encrypted_password":"ri4IhrQ5L07zK85O5nU17vr6p96Bz1/Cu4uoONk9rn/KNpr2wxDa","encrypted_password_confirm":"ri4IhrQ5L07zK85O5nU17vr6p96Bz1/Cu4uoONk9rn/KNpr2wxDa"}'
```

## 完整使用流程

### 登录流程

1. **获取会话密钥**
   ```bash
   curl -X POST http://localhost:31005/api/v1/auth/get-key
   ```

2. **加密凭据**
   ```bash
   node encrypt_login.cjs "密钥" "用户名" "密码" "会话ID"
   ```

3. **发送登录请求**
   ```bash
   curl -X POST http://localhost:31005/api/v1/auth/secure-login \
     -H "Content-Type: application/json" \
     -d '{"session_id":"...","encrypted_username":"...","encrypted_password":"..."}'
   ```

### 注册流程

1. **获取会话密钥**
   ```bash
   curl -X POST http://localhost:31005/api/v1/auth/get-key
   ```

2. **加密凭据**
   ```bash
   node encrypt_login.cjs --register "密钥" "用户名" "邮箱" "密码" "确认密码" "会话ID"
   ```

3. **发送注册请求**
   ```bash
   curl -X POST http://localhost:31005/api/v1/auth/secure-register \
     -H "Content-Type: application/json" \
     -d '{"session_id":"...","encrypted_username":"...","encrypted_email":"...","encrypted_password":"...","encrypted_password_confirm":"..."}'
   ```

## API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/v1/auth/get-key` | POST | 获取加密会话密钥 |
| `/api/v1/auth/secure-login` | POST | 安全登录（加密凭据） |
| `/api/v1/auth/secure-register` | POST | 安全注册（加密凭据） |

## 加密算法说明

- **算法**：AES-256-GCM
- **密钥长度**：32 字节（256 位）
- **nonce 长度**：12 字节
- **认证标签长度**：16 字节
- **输出格式**：Base64 编码的 `nonce(12) + authTag(16) + ciphertext`

## 注意事项

1. 会话密钥有效期为 5 分钟，过期后需要重新获取
2. 每个会话密钥只能使用一次，使用后立即失效
3. 建议在客户端实时获取密钥并加密，避免密钥泄露风险
4. 生产环境建议使用 HTTPS 传输，进一步提高安全性
