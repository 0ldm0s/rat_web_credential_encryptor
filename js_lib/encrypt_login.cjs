/**
 * 加密登录数据脚本
 *
 * 用法: node encrypt_login.cjs <key_base64> <username> <password> [session_id]
 *
 * 示例:
 *   node encrypt_login.cjs "4U/Raj8Sp4/0FUBag8DN53NgAooD6GEbDoHtioKHfbw=" "admin" "admin123"
 *   node encrypt_login.cjs "key=" "admin" "admin123" "custom-session-id"
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;

// 解析命令行参数
const args = process.argv.slice(2);
if (args.length < 3) {
  console.log('用法: node encrypt_login.cjs <key_base64> <username> <password> [session_id]');
  console.log('');
  console.log('参数:');
  console.log('  key_base64     - Base64编码的AES-256密钥');
  console.log('  username       - 用户名');
  console.log('  password       - 密码');
  console.log('  session_id     - 会话ID (可选，默认自动生成)');
  process.exit(1);
}

const keyBase64 = args[0];
const username = args[1];
const password = args[2];
const sessionId = args[3] || crypto.randomUUID();

// 验证密钥
const key = Buffer.from(keyBase64, 'base64');
if (key.length !== KEY_LENGTH) {
  console.error(`错误: 密钥必须是 ${KEY_LENGTH} 字节，当前为 ${key.length} 字节`);
  process.exit(1);
}

// 生成随机nonce
const nonce = crypto.randomBytes(12);

// 加密函数
function encrypt(text) {
  const cipher = crypto.createCipheriv(ALGORITHM, key, nonce);
  let encrypted = cipher.update(text, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Rust格式: nonce(12) + authTag(16) + ciphertext
  return Buffer.concat([nonce, authTag, encrypted]).toString('base64');
}

const encryptedUsername = encrypt(username);
const encryptedPassword = encrypt(password);

// 输出结果
console.log('=== 加密登录数据 ===');
console.log(`会话ID: ${sessionId}`);
console.log(`用户名: ${username} -> ${encryptedUsername}`);
console.log(`密码: ${password} -> ${encryptedPassword}`);
console.log('');

// 输出JSON格式（供curl使用）
console.log('--- JSON格式 ---');
console.log(JSON.stringify({
  session_id: sessionId,
  encrypted_username: encryptedUsername,
  encrypted_password: encryptedPassword
}, null, 2));

// 输出curl命令
console.log('');
console.log('--- curl命令 ---');
console.log(`curl -X POST http://localhost:31000/api/auth/secure-login \\
  -H "Content-Type: application/json" \\
  -d '${JSON.stringify({
    session_id: sessionId,
    encrypted_username: encryptedUsername,
    encrypted_password: encryptedPassword
  })}'`);
