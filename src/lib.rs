//! # rat_web_credential_encryptor
//!
//! Rust 加密库，用于 Web 应用中敏感数据的加密传输。
//!
//! ## 设计理念
//!
//! 在 HTTPS/TLS 之上提供应用层加密，确保：
//! - 负载均衡器无法看到明文敏感数据
//! - 服务器日志记录的是加密数据
//! - 密钥一次性使用，防重放攻击
//!
//! ## 使用流程（简化方案）
//!
//! 1. 服务器为每个会话生成临时 AES 密钥
//! 2. 客户端通过 HTTPS 获取密钥
//! 3. 客户端用 AES-GCM 加密敏感信息
//! 4. 服务器解密后立即删除密钥
//!
//! ## 示例
//!
//! ```rust
//! use rat_web_credential_encryptor::{
//!     session::SessionManager,
//!     encrypt_string, decrypt_string,
//! };
//! use std::time::Duration;
//!
//! // 创建会话管理器（5 分钟超时）
//! let manager = SessionManager::new(Duration::from_secs(300));
//!
//! // 创建新会话，获取密钥
//! let (session_id, key_bytes) = manager.create_session();
//!
//! // key_bytes 通过 HTTPS 安全发送给客户端
//! // 客户端使用 AES-GCM 加密数据后发送回来
//!
//! // 模拟客户端加密（实际客户端在浏览器中用 JS 加密）
//! let key = rat_web_credential_encryptor::SharedKey::new(key_bytes);
//! let encrypted_data = encrypt_string("敏感数据", &key)?;
//!
//! // 服务器解密（密钥使用后自动删除）
//! if let Some(key) = manager.get_and_remove(&session_id) {
//!     let decrypted = decrypt_string(&encrypted_data, &key)?;
//!     println!("解密成功: {}", decrypted);
//! }
//! # Ok::<(), rat_web_credential_encryptor::error::Error>(())
//! ```

pub mod cipher;
pub mod ecdh;
pub mod error;
pub mod key;
pub mod session;

// 导出常用类型
pub use error::{Error, Result};

// 导出会话管理
pub use session::SessionManager;
#[cfg(feature = "session-manager-cleanup")]
pub use session::SessionManagerWithCleanup;

// 导出密钥相关
pub use key::{generate_keypair, import_public_key, export_public_key, PrivateKey};
pub use p256::PublicKey as PublicKey;

// 导出 ECDH 相关
pub use ecdh::{derive_shared_secret, SharedKey};

// 导出加密相关
pub use cipher::{encrypt, decrypt, EncryptedData, encrypt_string, decrypt_string};
pub use cipher::{encrypt_ctr, decrypt_ctr, encrypt_string_ctr, decrypt_string_ctr};
