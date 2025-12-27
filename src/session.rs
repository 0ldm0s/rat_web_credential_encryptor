//! 会话和密钥管理器
//!
//! 提供安全的密钥生命周期管理，确保密钥一次性使用

use crate::ecdh::SharedKey;
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 会话数据
struct SessionData {
    /// AES 密钥
    key: SharedKey,
    /// 创建时间
    created_at: Instant,
}

/// 会话管理器
///
/// 管理临时密钥的生命周期，确保密钥：
/// - 只能使用一次
/// - 超时自动删除
/// - 使用后立即删除
pub struct SessionManager {
    /// 会话存储：session_id -> (密钥, 创建时间)
    sessions: Arc<Mutex<HashMap<String, SessionData>>>,
    /// 会话超时时间
    session_timeout: Duration,
}

impl SessionManager {
    /// 创建新的会话管理器
    ///
    /// # 参数
    /// - `session_timeout`: 会话超时时间，推荐 5-10 分钟
    ///
    /// # 示例
    /// ```rust
    /// use std::time::Duration;
    /// use rat_web_credential_encryptor::session::SessionManager;
    ///
    /// // 5 分钟超时
    /// let manager = SessionManager::new(Duration::from_secs(300));
    /// ```
    pub fn new(session_timeout: Duration) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_timeout,
        }
    }

    /// 使用默认超时（5 分钟）创建会话管理器
    pub fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }

    /// 创建新会话，生成随机 AES-256 密钥
    ///
    /// # 返回
    /// - (session_id, key_bytes): 会话 ID 和密钥的字节表示（32 字节）
    ///
    /// # 注意
    /// 密钥字节应该安全地传输给客户端（通过 HTTPS）
    pub fn create_session(&self) -> (String, [u8; 32]) {
        let session_id = uuid::Uuid::new_v4().to_string();
        let key_bytes = rand::random::<[u8; 32]>();
        let key = SharedKey::new(key_bytes);

        let session_data = SessionData {
            key,
            created_at: Instant::now(),
        };

        self.sessions.lock().unwrap().insert(session_id.clone(), session_data);

        (session_id, key_bytes)
    }

    /// 获取密钥并删除会话（一次性使用）
    ///
    /// # 参数
    /// - `session_id`: 会话 ID
    ///
    /// # 返回
    /// - `Some(SharedKey)`: 密钥存在且已删除
    /// - `None`: 会话不存在或已过期/已使用
    ///
    /// # 安全性
    /// 密钥在返回后立即从内存中删除，无法再次使用
    pub fn get_and_remove(&self, session_id: &str) -> Option<SharedKey> {
        self.sessions.lock().unwrap().remove(session_id).map(|data| data.key)
    }

    /// 检查会话是否存在（不删除）
    pub fn exists(&self, session_id: &str) -> bool {
        self.sessions.lock().unwrap().contains_key(session_id)
    }

    /// 清理过期会话
    ///
    /// 删除所有超过超时时间的会话
    ///
    /// # 返回
    /// 清理的会话数量
    pub fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap();
        let initial_count = sessions.len();

        sessions.retain(|_, data| {
            now.duration_since(data.created_at) < self.session_timeout
        });

        initial_count - sessions.len()
    }

    /// 获取当前活跃会话数
    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

/// 异步会话管理器（带自动清理后台任务）
///
/// 自动定期清理过期会话
///
/// 需启用 `session-manager-cleanup` feature
#[cfg(feature = "session-manager-cleanup")]
pub struct SessionManagerWithCleanup {
    inner: SessionManager,
    _handle: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "session-manager-cleanup")]
impl SessionManagerWithCleanup {
    /// 创建带自动清理的会话管理器
    ///
    /// # 参数
    /// - `session_timeout`: 会话超时时间
    /// - `cleanup_interval`: 清理间隔时间，推荐超时时间的一半
    pub fn new(session_timeout: Duration, cleanup_interval: Duration) -> Self {
        let inner = SessionManager::new(session_timeout);
        let sessions = inner.sessions.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut sessions = sessions.lock().unwrap();
                sessions.retain(|_, data| {
                    now.duration_since(data.created_at) < session_timeout
                });
            }
        });

        Self {
            inner,
            _handle: handle,
        }
    }

    /// 创建新会话
    pub fn create_session(&self) -> (String, [u8; 32]) {
        self.inner.create_session()
    }

    /// 获取密钥并删除会话
    pub fn get_and_remove(&self, session_id: &str) -> Option<SharedKey> {
        self.inner.get_and_remove(session_id)
    }

    /// 检查会话是否存在
    pub fn exists(&self, session_id: &str) -> bool {
        self.inner.exists(session_id)
    }

    /// 获取当前活跃会话数
    pub fn session_count(&self) -> usize {
        self.inner.session_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_get_session() {
        let manager = SessionManager::default();
        let (session_id, key_bytes) = manager.create_session();

        assert!(manager.exists(&session_id));

        let key = manager.get_and_remove(&session_id).unwrap();
        assert_eq!(key.as_bytes(), &key_bytes);

        // 密钥已被删除
        assert!(!manager.exists(&session_id));
        assert!(manager.get_and_remove(&session_id).is_none());
    }

    #[test]
    fn test_session_timeout() {
        let manager = SessionManager::new(Duration::from_millis(100));
        let (session_id, _) = manager.create_session();

        // 等待超时
        std::thread::sleep(Duration::from_millis(150));

        // 清理过期会话
        let cleaned = manager.cleanup_expired();
        assert_eq!(cleaned, 1);

        assert!(!manager.exists(&session_id));
    }

    #[test]
    fn test_one_time_use() {
        let manager = SessionManager::default();
        let (session_id, _) = manager.create_session();

        // 第一次获取成功
        assert!(manager.get_and_remove(&session_id).is_some());

        // 第二次获取失败
        assert!(manager.get_and_remove(&session_id).is_none());
    }
}
