# rat_web_credential_encryptor

Rust 加密库，用于 Web 应用中敏感数据（如密码）的安全传输。

## 特性

- **应用层加密**：在 HTTPS/TLS 之上提供额外的加密保护
- **一次性密钥**：密钥仅可使用一次，使用后立即销毁
- **会话管理**：内置 `SessionManager` 管理密钥生命周期
- **双模式支持**：AES-256-GCM（认证加密）和 AES-256-CTR（与 crypto-js 兼容）
- **防重放攻击**：密钥有超时机制（默认5分钟）

## 适用场景

```
浏览器 --HTTPS--> 负载均衡器 --HTTPS--> 应用服务器
                    ↓
               (无法看到明文密码)
```

- 负载均衡器终止 TLS，但不应看到明文敏感数据
- 服务器日志记录的是加密数据
- 需要比 HTTPS 更高的安全保证

## 安装

```toml
[dependencies]
rat_web_credential_encryptor = "0.1"
```

## 快速开始

### 1. 创建会话管理器

```rust
use rat_web_credential_encryptor::SessionManager;
use std::time::Duration;

// 5分钟超时
let manager = SessionManager::new(Duration::from_secs(300));
```

### 2. 生成密钥并发送给客户端

```rust
// 创建新会话，获取密钥
let (session_id, key_bytes) = manager.create_session();

// 将密钥转为 Base64 通过 HTTPS 发送给客户端
let key_b64 = base64ct::Base64::encode_string(&key_bytes);

// 返回给前端: { "session_id": "...", "key": "..." }
```

### 3. 前端加密数据

```javascript
// 使用 crypto-js 加密（CTR 模式）
import CryptoJS from 'crypto-js';

const key = CryptoJS.enc.Base64.parse(keyFromServer);
const nonce = CryptoJS.lib.WordArray.create(randomNonce);

const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
    mode: CryptoJS.mode.CTR,
    padding: CryptoJS.pad.NoPadding,
    iv: nonce
});

// 发送 nonce + ciphertext 给服务器
```

### 4. 后端解密

```rust
use rat_web_credential_encryptor::decrypt_string_ctr;

// 获取并删除密钥（一次性使用）
let key = manager.get_and_remove(&session_id)?;

// 解密数据
let decrypted = decrypt_string_ctr(&encrypted_data, &key)?;
// decrypted = "username:password"
```

## API 文档

### SessionManager

管理临时密钥的生命周期。

```rust
impl SessionManager {
    // 创建新的会话管理器
    pub fn new(session_timeout: Duration) -> Self;

    // 创建新会话，返回 (session_id, key_bytes)
    pub fn create_session(&self) -> (String, [u8; 32]);

    // 获取密钥并删除会话（一次性使用）
    pub fn get_and_remove(&self, session_id: &str) -> Option<SharedKey>;

    // 检查会话是否存在
    pub fn exists(&self, session_id: &str) -> bool;

    // 清理过期会话
    pub fn cleanup_expired(&self) -> usize;
}
```

### 加密/解密（CTR 模式）

与 crypto-js 兼容。

```rust
// 加密数据
pub fn encrypt_ctr(plaintext: &[u8], key: &SharedKey) -> String;

// 解密数据
pub fn decrypt_ctr(ciphertext_b64: &str, key: &SharedKey) -> Result<Vec<u8>>;

// 便捷函数：加密字符串
pub fn encrypt_string_ctr(plaintext: &str, key: &SharedKey) -> String;

// 便捷函数：解密字符串
pub fn decrypt_string_ctr(ciphertext_b64: &str, key: &SharedKey) -> Result<String>;
```

### 加密/解密（GCM 模式）

提供认证加密。

```rust
use rat_web_credential_encryptor::{encrypt, decrypt, EncryptedData};

// 加密
let encrypted = encrypt(plaintext, &key)?;

// 解密
let decrypted = decrypt(&encrypted, &key)?;

// 便捷函数
pub fn encrypt_string(plaintext: &str, key: &SharedKey) -> Result<String>;
pub fn decrypt_string(ciphertext_b64: &str, key: &SharedKey) -> Result<String>;
```

## 示例

### 完整登录示例

项目包含一个完整的登录示例，展示如何使用本库：

```bash
cd examples/login_server
cargo run
```

访问 `http://127.0.0.1:3000` 进行测试。

示例流程：
1. 前端请求 `/api/key` 获取一次性密钥
2. 使用 AES-CTR 加密用户名和密码
3. 发送到 `/api/login`
4. 后端解密并验证

## 安全注意事项

1. **必须使用 HTTPS**：密钥传输必须通过 TLS 保护
2. **密钥一次性使用**：密钥使用后立即从内存删除
3. **合理的超时时间**：建议 5-10 分钟
4. **定期清理**：调用 `cleanup_expired()` 清理过期会话

## 许可证

LGPL-3.0-or-later（GNU Lesser General Public License v3.0 or later）

## 贡献

欢迎提交 Issue 和 Pull Request。
