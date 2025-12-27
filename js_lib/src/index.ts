/**
 * rat-web-credential-encryptor
 *
 * JavaScript 加密库，与 rat_web_credential_encryptor Rust 库配合使用
 *
 * ## 使用流程
 *
 * 1. 前端生成密钥对
 * 2. 将公钥发送给后端
 * 3. 接收后端公钥
 * 4. 使用 ECDH 派生共享密钥
 * 5. 使用共享密钥进行 AES-GCM 加密通信
 *
 * ## 示例
 *
 * ```typescript
 * import {
 *   generateKeyPair,
 *   exportPublicKey,
 *   importPublicKey,
 *   deriveSharedKey,
 *   encryptString,
 *   decryptString,
 * } from 'rat-web-credential-encryptor';
 *
 * // 前端生成密钥对
 * const { privateKey, publicKey } = await generateKeyPair();
 *
 * // 导出公钥发送给后端
 * const pubKeyBytes = await exportPublicKey(publicKey);
 *
 * // 假设从后端收到公钥
 * const serverPubKey = await importPublicKey(serverPubKeyBytes);
 *
 * // 派生共享密钥
 * const sharedKey = await deriveSharedKey(privateKey, serverPubKey);
 *
 * // 加密敏感数据
 * const ciphertext = await encryptString('敏感密码', sharedKey);
 *
 * // 解密收到的数据
 * const decrypted = await decryptString(ciphertext, sharedKey);
 * ```
 */

export {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  deriveSharedKey,
  encrypt,
  decrypt,
  encryptString,
  decryptString,
  bytesToHex,
  hexToBytes,
  CryptoError,
} from './crypto.js';

export type { KeyPair } from './crypto.js';
