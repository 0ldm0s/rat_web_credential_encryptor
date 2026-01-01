/**
 * AES-256-GCM 加密脚本（与 Rust 兼容）
 *
 * 格式: nonce(12) + authTag(16) + ciphertext
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const NONCE_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;

/**
 * AES-256-GCM 加密器（与 Rust 兼容）
 */
class RustCompatAESGCM {
  constructor(key) {
    if (key.length !== KEY_LENGTH) {
      throw new Error(`密钥必须是 ${KEY_LENGTH} 字节`);
    }
    this.key = key;
  }

  /**
   * 加密字符串，返回 Base64
   * Rust 格式: nonce(12) + authTag(16) + ciphertext
   */
  encryptString(plaintext) {
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, this.key, nonce);

    let encrypted = cipher.update(plaintext, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Rust 格式: nonce + authTag + ciphertext
    const result = Buffer.concat([nonce, authTag, encrypted]);
    return result.toString('base64');
  }

  /**
   * 解密 Base64 编码的字符串
   */
  decryptString(ciphertextB64) {
    const data = Buffer.from(ciphertextB64, 'base64');

    if (data.length < NONCE_LENGTH + AUTH_TAG_LENGTH) {
      throw new Error('加密数据过短');
    }

    const nonce = data.slice(0, NONCE_LENGTH);
    const authTag = data.slice(NONCE_LENGTH, NONCE_LENGTH + AUTH_TAG_LENGTH);
    const encrypted = data.slice(NONCE_LENGTH + AUTH_TAG_LENGTH);

    const decipher = crypto.createDecipheriv(ALGORITHM, this.key, nonce);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('utf8');
  }

  /**
   * 加密字符串，返回 Buffer（用于 Rust 解密）
   */
  encryptToBuffer(plaintext) {
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, this.key, nonce);

    let encrypted = cipher.update(plaintext, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Rust 格式: nonce + authTag + ciphertext
    return Buffer.concat([nonce, authTag, encrypted]);
  }

  /**
   * 解密 Buffer
   */
  decryptFromBuffer(buffer) {
    if (buffer.length < NONCE_LENGTH + AUTH_TAG_LENGTH) {
      throw new Error('加密数据过短');
    }

    const nonce = buffer.slice(0, NONCE_LENGTH);
    const authTag = buffer.slice(NONCE_LENGTH, NONCE_LENGTH + AUTH_TAG_LENGTH);
    const encrypted = buffer.slice(NONCE_LENGTH + AUTH_TAG_LENGTH);

    const decipher = crypto.createDecipheriv(ALGORITHM, this.key, nonce);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
  }
}

// 测试
async function main() {
  const keyBase64 = process.argv[2] || '6dnhxR+FsYstQTaBk20AODPp1Myn1ZtMTfRjYO0uXVU=';
  const sessionId = process.argv[3] || 'test-session-id';

  const key = Buffer.from(keyBase64, 'base64');

  console.log('=== AES-256-GCM 加密测试（与 Rust 兼容）===');
  console.log('密钥 (Base64):', keyBase64);
  console.log('密钥长度:', key.length, '字节');
  console.log('格式: nonce(12) + authTag(16) + ciphertext');
  console.log('');

  const aes = new RustCompatAESGCM(key);

  // 测试加密
  const testUsername = 'admin';
  const testPassword = 'password123';

  console.log('--- 测试加密 ---');
  console.log('用户名:', testUsername);
  console.log('密码:', testPassword);

  const encryptedUsername = aes.encryptString(testUsername);
  const encryptedPassword = aes.encryptString(testPassword);

  console.log('加密用户名:', encryptedUsername);
  console.log('加密密码:', encryptedPassword);

  // 测试解密
  console.log('\n--- 测试解密 ---');
  const decryptedUsername = aes.decryptString(encryptedUsername);
  const decryptedPassword = aes.decryptString(encryptedPassword);

  console.log('解密用户名:', decryptedUsername);
  console.log('解密密码:', decryptedPassword);

  console.log('\n--- 验证 ---');
  console.log('用户名匹配:', decryptedUsername === testUsername ? '✅' : '❌');
  console.log('密码匹配:', decryptedPassword === testPassword ? '✅' : '❌');

  // 输出 JSON
  console.log('\n--- JSON 输出（供 curl 使用）---');
  console.log(JSON.stringify({
    session_id: sessionId,
    encrypted_username: encryptedUsername,
    encrypted_password: encryptedPassword
  }, null, 2));
}

main().catch(console.error);
