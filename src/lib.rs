//! # rat_web_credential_encryptor
//!
//! Rust + JavaScript 跨语言加密库，用于 Web 前端与 Rust 后端之间的敏感数据加密传输。
//!
//! ## 使用流程
//!
//! 1. 后端生成密钥对
//! 2. 后端将公钥发送给前端
//! 3. 前端生成自己的密钥对
//! 4. 双方使用 ECDH 派生共享密钥
//! 5. 使用共享密钥进行 AES-GCM 加密通信
//!
//! ## 示例
//!
//! ```rust
//! use rat_web_credential_encryptor::{
//!     generate_keypair, export_public_key, import_public_key,
//!     derive_shared_secret, encrypt_string, decrypt_string,
//! };
//!
//! // 后端生成密钥对
//! let (server_priv, server_pub) = generate_keypair();
//!
//! // 前端也生成密钥对
//! let (client_priv, client_pub) = generate_keypair();
//!
//! // 导出公钥以便在网络传输
//! let client_pub_bytes = export_public_key(&client_pub);
//!
//! // 后端导入前端公钥
//! let client_pub = import_public_key(&client_pub_bytes)?;
//!
//! // 双方派生共享密钥（结果相同）
//! let server_shared = derive_shared_secret(&server_priv, &client_pub)?;
//! let client_shared = derive_shared_secret(&client_priv, &server_pub)?;
//! assert_eq!(server_shared.as_bytes(), client_shared.as_bytes());
//!
//! // 加密数据
//! let ciphertext = encrypt_string("敏感数据", &server_shared)?;
//! let decrypted = decrypt_string(&ciphertext, &client_shared)?;
//! assert_eq!("敏感数据", decrypted);
//! # Ok::<(), rat_web_credential_encryptor::error::Error>(())
//! ```

pub mod cipher;
pub mod ecdh;
pub mod error;
pub mod key;

// 导出常用类型
pub use error::{Error, Result};

// 导出密钥相关
pub use key::{generate_keypair, import_public_key, export_public_key, PrivateKey};
pub use p256::PublicKey as PublicKey;

// 导出 ECDH 相关
pub use ecdh::{derive_shared_secret, SharedKey};

// 导出加密相关
pub use cipher::{encrypt, decrypt, EncryptedData, encrypt_string, decrypt_string};
