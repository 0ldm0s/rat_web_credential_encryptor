//! AES-256 加密/解密
//!
//! 支持 GCM 和 CTR 两种模式：
//! - GCM：提供认证加密，用于需要数据完整性验证的场景
//! - CTR：与 crypto-js 兼容，用于纯 JS 前端交互

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use ctr::Ctr128BE;
use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use base64ct::{Base64, Encoding};

use crate::ecdh::SharedKey;
use crate::error::{Error, Result};

/// 加密后的数据
///
/// 包含 nonce 和密文，格式为: nonce(12字节) + ciphertext
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedData {
    /// Nonce (96 位，12 字节) + 密文
    data: Vec<u8>,
}

impl EncryptedData {
    /// 创建新的加密数据
    fn new(nonce: &[u8; 12], ciphertext: &[u8]) -> Self {
        let mut data = Vec::with_capacity(12 + ciphertext.len());
        data.extend_from_slice(nonce);
        data.extend_from_slice(ciphertext);
        Self { data }
    }

    /// 获取 nonce
    pub fn nonce(&self) -> &[u8; 12] {
        self.data[0..12].try_into().unwrap()
    }

    /// 获取密文
    pub fn ciphertext(&self) -> &[u8] {
        &self.data[12..]
    }

    /// 转换为 Base64 字符串
    pub fn to_base64(&self) -> String {
        Base64::encode_string(&self.data)
    }

    /// 从 Base64 字符串解析
    pub fn from_base64(s: &str) -> Result<Self> {
        let data = Base64::decode_vec(s).map_err(|e| Error::Encoding(format!("Base64 解码失败: {}", e)))?;
        if data.len() < 12 {
            return Err(Error::InvalidInput("加密数据过短".into()));
        }
        Ok(Self { data })
    }
}

/// 使用 AES-256-GCM 加密数据
///
/// # 参数
/// - `plaintext`: 明文数据
/// - `key`: 32 字节的共享密钥
///
/// # 返回
/// 包含 nonce 和密文的加密数据
pub fn encrypt(plaintext: &[u8], key: &SharedKey) -> Result<EncryptedData> {
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| Error::Crypto(format!("加密失败: {}", e)))?;

    let nonce_array: [u8; 12] = nonce.as_slice().try_into().unwrap();
    Ok(EncryptedData::new(&nonce_array, &ciphertext))
}

/// 使用 AES-256-GCM 解密数据
///
/// # 参数
/// - `encrypted`: 加密数据
/// - `key`: 32 字节的共享密钥
///
/// # 返回
/// 解密后的明文
pub fn decrypt(encrypted: &EncryptedData, key: &SharedKey) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    let nonce = Nonce::from_slice(encrypted.nonce());

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext())
        .map_err(|e| Error::Crypto(format!("解密失败: {}", e)))?;

    Ok(plaintext)
}

/// 便捷函数：加密字符串并返回 Base64
pub fn encrypt_string(plaintext: &str, key: &SharedKey) -> Result<String> {
    encrypt(plaintext.as_bytes(), key).map(|e| e.to_base64())
}

/// 便捷函数：从 Base64 解密为字符串
pub fn decrypt_string(ciphertext_b64: &str, key: &SharedKey) -> Result<String> {
    let encrypted = EncryptedData::from_base64(ciphertext_b64)?;
    let bytes = decrypt(&encrypted, key)?;
    String::from_utf8(bytes).map_err(|e| Error::Encoding(format!("UTF-8 解码失败: {}", e)))
}

// ==================== CTR 模式（与 crypto-js 兼容）====================

/// CTR 模式加密数据（与 crypto-js 兼容）
///
/// # 参数
/// - `plaintext`: 明文数据
/// - `key`: 32 字节的共享密钥
///
/// # 返回
/// Base64 编码的 nonce(16字节) + 密文
pub fn encrypt_ctr(plaintext: &[u8], key: &SharedKey) -> String {
    use rand::RngCore;

    let mut nonce = [0u8; 16];  // CTR 使用 16 字节 nonce
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut cipher = Ctr128BE::<Aes256>::new_from_slices(key.as_bytes(), &nonce)
        .expect("CTR 初始化失败");

    let mut ciphertext = plaintext.to_vec();
    cipher.apply_keystream(&mut ciphertext);

    // 组合 nonce || ciphertext
    let mut result = Vec::with_capacity(16 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Base64::encode_string(&result)
}

/// CTR 模式解密数据（与 crypto-js 兼容）
///
/// # 参数
/// - `ciphertext_b64`: Base64 编码的 nonce(16字节) + 密文
/// - `key`: 32 字节的共享密钥
///
/// # 返回
/// 解密后的明文
pub fn decrypt_ctr(ciphertext_b64: &str, key: &SharedKey) -> Result<Vec<u8>> {
    let data = Base64::decode_vec(ciphertext_b64)
        .map_err(|e| Error::Encoding(format!("Base64 解码失败: {}", e)))?;

    if data.len() < 16 {
        return Err(Error::InvalidInput("加密数据过短".into()));
    }

    let nonce = &data[0..16];
    let ciphertext = &data[16..];

    let mut cipher = Ctr128BE::<Aes256>::new_from_slices(key.as_bytes(), nonce)
        .map_err(|e| Error::Crypto(format!("CTR 初始化失败: {}", e)))?;

    let mut plaintext = ciphertext.to_vec();
    cipher.apply_keystream(&mut plaintext);

    Ok(plaintext)
}

/// CTR 模式便捷函数：加密字符串
pub fn encrypt_string_ctr(plaintext: &str, key: &SharedKey) -> String {
    encrypt_ctr(plaintext.as_bytes(), key)
}

/// CTR 模式便捷函数：从 Base64 解密为字符串
pub fn decrypt_string_ctr(ciphertext_b64: &str, key: &SharedKey) -> Result<String> {
    let bytes = decrypt_ctr(ciphertext_b64, key)?;
    String::from_utf8(bytes).map_err(|e| Error::Encoding(format!("UTF-8 解码失败: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_key() -> SharedKey {
        SharedKey::new([42u8; 32])
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = make_test_key();
        let plaintext = b"Hello, world!";

        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_string() {
        let key = make_test_key();
        let plaintext = "敏感密码123!@#";

        let b64 = encrypt_string(plaintext, &key).unwrap();
        let decrypted = decrypt_string(&b64, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = make_test_key();
        let mut key2_bytes = [42u8; 32];
        key2_bytes[0] = 0;
        let key2 = SharedKey::new(key2_bytes);

        let plaintext = b"secret data";
        let encrypted = encrypt(plaintext, &key1).unwrap();

        // 用错误的密钥解密应该失败
        assert!(decrypt(&encrypted, &key2).is_err());
    }

    #[test]
    fn test_empty_data() {
        let key = make_test_key();
        let plaintext = b"";

        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_long_data() {
        let key = make_test_key();
        let plaintext = vec![b'X'; 10000];

        let encrypted = encrypt(&plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
