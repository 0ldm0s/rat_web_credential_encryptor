//! 错误类型定义

use std::fmt;

/// 库的统一错误类型
#[derive(Debug)]
pub enum Error {
    /// 密钥相关错误
    Key(String),

    /// 加密/解密错误
    Crypto(String),

    /// 编码/解码错误
    Encoding(String),

    /// 无效输入
    InvalidInput(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Key(msg) => write!(f, "密钥错误: {}", msg),
            Error::Crypto(msg) => write!(f, "加密错误: {}", msg),
            Error::Encoding(msg) => write!(f, "编码错误: {}", msg),
            Error::InvalidInput(msg) => write!(f, "无效输入: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

/// 结果类型别名
pub type Result<T> = std::result::Result<T, Error>;

// 从 p256 错误转换
impl From<p256::elliptic_curve::Error> for Error {
    fn from(err: p256::elliptic_curve::Error) -> Self {
        Error::Key(err.to_string())
    }
}

// 从 aes-gcm 错误转换
impl From<aes_gcm::Error> for Error {
    fn from(err: aes_gcm::Error) -> Self {
        Error::Crypto(err.to_string())
    }
}
