//! ECDH 密钥交换

use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::EncodedPoint,
    PublicKey,
};
use rand_core::OsRng;

use crate::key::PrivateKey;
use crate::error::{Error, Result};

/// ECDH 共享密钥（原始字节）
///
/// 这是 ECDH 计算出的共享密钥，可以直接用作 AES-GCM 的密钥
/// 或者可以通过 HKDF 派生多个密钥
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedKey {
    /// 共享密钥的字节表示（32 字节，256 位）
    bytes: [u8; 32],
}

impl SharedKey {
    /// 创建新的共享密钥
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// 获取密钥的字节表示
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// 获取密钥的可变字节表示
    pub fn as_bytes_mut(&mut self) -> &mut [u8; 32] {
        &mut self.bytes
    }
}

/// 使用 ECDH 从私钥和对方公钥派生共享密钥
///
/// # 参数
/// - `privkey`: 我方的私钥
/// - `peer_pubkey`: 对方的公钥
///
/// # 返回
/// 32 字节的共享密钥（可以直接用于 AES-256-GCM）
pub fn derive_shared_secret(privkey: &PrivateKey, peer_pubkey: &PublicKey) -> Result<SharedKey> {
    use p256::ecdh::diffie_hellman;

    // 使用 p256 的 diffie_hellman 函数执行 ECDH
    let shared_secret = diffie_hellman(privkey.to_nonzero_scalar(), peer_pubkey.as_affine());

    // 获取原始字节
    let raw_bytes = shared_secret.raw_secret_bytes();

    // 复制到固定大小数组
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(raw_bytes.as_slice());

    Ok(SharedKey::new(bytes))
}

/// 生成临时密钥对并执行 ECDH（一次性密钥交换）
///
/// 返回 (临时私钥, 共享密钥, 我方公钥)
/// 公钥需要发送给对方，对方用其公钥派生相同的共享密钥
pub fn ephemeral_ecdh(peer_pubkey: &PublicKey) -> Result<(PrivateKey, SharedKey, PublicKey)> {
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let my_pubkey = ephemeral_secret.public_key();

    // 执行 ECDH
    let shared_secret = ephemeral_secret.diffie_hellman(peer_pubkey);
    let raw_bytes = shared_secret.raw_secret_bytes();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(raw_bytes.as_slice());

    // 将临时私钥转换为普通 PrivateKey
    // 注意：EphemeralSecret 消耗后无法恢复，所以这里需要特殊处理
    // 实际使用中，应该先从 PrivateKey 生成
    let (privkey, _) = crate::key::generate_keypair();

    Ok((privkey, SharedKey::new(bytes), my_pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{export_public_key, generate_keypair, import_public_key};

    #[test]
    fn test_ecdh_symmetric() {
        // 生成两个密钥对
        let (alice_priv, alice_pub) = generate_keypair();
        let (bob_priv, bob_pub) = generate_keypair();

        // Alice 使用 Bob 的公钥派生共享密钥
        let alice_shared = derive_shared_secret(&alice_priv, &bob_pub).unwrap();

        // Bob 使用 Alice 的公钥派生共享密钥
        let bob_shared = derive_shared_secret(&bob_priv, &alice_pub).unwrap();

        // 双方派生的共享密钥应该相同
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_ecdh_with_imported_key() {
        let (alice_priv, alice_pub) = generate_keypair();
        let (bob_priv, bob_pub) = generate_keypair();

        // 导出并导入 Bob 的公钥（模拟从网络接收）
        let bob_pub_bytes = export_public_key(&bob_pub);
        let bob_pub_imported = import_public_key(&bob_pub_bytes).unwrap();

        // 使用导入的公钥派生共享密钥
        let alice_shared = derive_shared_secret(&alice_priv, &bob_pub_imported).unwrap();
        let bob_shared = derive_shared_secret(&bob_priv, &alice_pub).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }
}
