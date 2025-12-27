//! 密钥生成、导入和导出

use p256::{ecdsa::SigningKey, PublicKey, SecretKey};
use rand_core::OsRng;

use crate::error::{Error, Result};

/// P-256 私钥（用于 ECDH）
pub type PrivateKey = SecretKey;

/// 导出公钥为原始字节数组（SEC1 压缩格式）
///
/// 返回的字节数组可以通过 `import_public_key` 在 JavaScript 端导入
pub fn export_public_key(pubkey: &PublicKey) -> Vec<u8> {
    pubkey.to_sec1_bytes().to_vec()
}

/// 从原始字节数组导入公钥
///
/// 接受 SEC1 格式（压缩或非压缩）
pub fn import_public_key(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(bytes).map_err(|e| Error::Key(format!("无效公钥: {}", e)))
}

/// 生成新的 P-256 密钥对
///
/// 返回 (私钥, 公钥)
pub fn generate_keypair() -> (PrivateKey, PublicKey) {
    let signing_key = SigningKey::random(&mut OsRng);
    let secret_key: PrivateKey = signing_key.into();
    let public_key = secret_key.public_key();
    (secret_key, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (_priv_key, pub_key) = generate_keypair();
        // 公钥导出和导入应该是可逆的
        let exported = export_public_key(&pub_key);
        let imported = import_public_key(&exported).unwrap();
        assert_eq!(pub_key, imported);
    }

    #[test]
    fn test_export_import_roundtrip() {
        let (_priv_key, pub_key) = generate_keypair();
        let exported = export_public_key(&pub_key);
        let imported = import_public_key(&exported).unwrap();
        assert_eq!(pub_key, imported);
    }
}
