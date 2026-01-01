//! 测试 Rust 能否解密 JS 加密的数据

use rat_web_credential_encryptor::{encrypt_string, decrypt_string, SharedKey};
use base64ct::Encoding;

fn main() {
    // 测试密钥
    let key_bytes = base64ct::Base64::decode_vec("6dnhxR+FsYstQTaBk20AODPp1Myn1ZtMTfRjYO0uXVU=").unwrap();
    let key = SharedKey::new(key_bytes.try_into().unwrap());

    // 这是 JS 加密的用户名
    let js_encrypted_username = "dFLWcc9De79xKbJHgWXDVquGbOWMfaCCfc7BeTuH5/5G";
    let js_encrypted_password = "S9uix4faq5lqqboHjFGx0Hs2TZ+D6S0HtCHV7NqCM6Aw3Cxac9Rz";

    println!("JS 加密用户名: {}", js_encrypted_username);
    println!("JS 加密密码: {}", js_encrypted_password);

    // 尝试解密
    match decrypt_string(js_encrypted_username, &key) {
        Ok(decrypted) => println!("Rust 解密用户名成功: {}", decrypted),
        Err(e) => println!("Rust 解密用户名失败: {:?}", e),
    }

    match decrypt_string(js_encrypted_password, &key) {
        Ok(decrypted) => println!("Rust 解密密码成功: {}", decrypted),
        Err(e) => println!("Rust 解密密码失败: {:?}", e),
    }

    // 测试反过来：Rust 加密，JS 解密
    println!("\n--- 测试 Rust 加密，JS 解密 ---");
    let rust_encrypted = encrypt_string("admin", &key).unwrap();
    println!("Rust 加密用户名: {}", rust_encrypted);
}
