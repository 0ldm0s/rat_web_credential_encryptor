/**
 * 加密数据脚本（支持登录和注册）
 *
 * 用法:
 *   登录: node encrypt_login.cjs <key> <username> <password> [session_id]
 *   注册: node encrypt_login.cjs --register <key> <username> <email> <password> <password_confirm> [session_id]
 *
 * 示例:
 *   登录: node encrypt_login.cjs "key=" "admin" "admin123"
 *   注册: node encrypt_login.cjs --register "key=" "newuser" "user@test.com" "password123" "password123"
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;

// 解析命令行参数
const args = process.argv.slice(2);

// 检查是否是注册模式
const isRegister = args[0] === '--register';
if (isRegister) args.shift();

if (isRegister) {
  if (args.length < 5) {
    console.log('=== 注册模式 ===');
    console.log('用法: node encrypt_login.cjs --register <key_base64> <username> <email> <password> <password_confirm> [session_id]');
    process.exit(1);
  }

  const [keyBase64, username, email, password, passwordConfirm, sessionId] = args;

  // 验证密钥
  const key = Buffer.from(keyBase64, 'base64');
  if (key.length !== KEY_LENGTH) {
    console.error(`错误: 密钥必须是 ${KEY_LENGTH} 字节`);
    process.exit(1);
  }

  const nonce = crypto.randomBytes(12);

  function encrypt(text) {
    const cipher = crypto.createCipheriv(ALGORITHM, key, nonce);
    let enc = cipher.update(text, 'utf8');
    enc = Buffer.concat([enc, cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([nonce, authTag, enc]).toString('base64');
  }

  const result = {
    session_id: sessionId || crypto.randomUUID(),
    encrypted_username: encrypt(username),
    encrypted_email: encrypt(email),
    encrypted_password: encrypt(password),
    encrypted_password_confirm: encrypt(passwordConfirm)
  };

  console.log('=== 加密注册数据 ===');
  console.log(JSON.stringify(result, null, 2));
  console.log('');
  console.log(`curl -X POST http://localhost:31005/api/v1/auth/secure-register -H "Content-Type: application/json" -d '${JSON.stringify(result)}'`);
} else {
  // 登录模式
  if (args.length < 3) {
    console.log('=== 登录模式 ===');
    console.log('用法: node encrypt_login.cjs <key_base64> <username> <password> [session_id]');
    process.exit(1);
  }

  const [keyBase64, username, password, sessionId] = args;

  // 验证密钥
  const key = Buffer.from(keyBase64, 'base64');
  if (key.length !== KEY_LENGTH) {
    console.error(`错误: 密钥必须是 ${KEY_LENGTH} 字节`);
    process.exit(1);
  }

  const nonce = crypto.randomBytes(12);

  function encrypt(text) {
    const cipher = crypto.createCipheriv(ALGORITHM, key, nonce);
    let enc = cipher.update(text, 'utf8');
    enc = Buffer.concat([enc, cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([nonce, authTag, enc]).toString('base64');
  }

  const result = {
    session_id: sessionId || crypto.randomUUID(),
    encrypted_username: encrypt(username),
    encrypted_password: encrypt(password)
  };

  console.log('=== 加密登录数据 ===');
  console.log(JSON.stringify(result, null, 2));
  console.log('');
  console.log(`curl -X POST http://localhost:31000/api/auth/secure-login -H "Content-Type: application/json" -d '${JSON.stringify(result)}'`);
}
