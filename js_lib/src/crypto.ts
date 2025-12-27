/**
 * Web Crypto API 封装
 *
 * 提供与 Rust 端 rat_web_credential_encryptor 兼容的加密功能
 */

// 算法标识常量
const ALGORITHM = {
  ECDH: { name: 'ECDH', namedCurve: 'P-256' },
  AES_GCM: { name: 'AES-GCM', length: 256 },
} as const;

/**
 * 密钥类型
 */
export type KeyPair = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
};

/**
 * 错误类型
 */
export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoError';
  }
}

/**
 * 生成 P-256 密钥对
 *
 * @returns Promise<CryptoKeyPair> P-256 密钥对
 */
export async function generateKeyPair(): Promise<KeyPair> {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveKey', 'deriveBits']
    );
    return keyPair as KeyPair;
  } catch (e) {
    throw new CryptoError(`生成密钥对失败: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * 导出公钥为原始字节（SEC1 格式）
 *
 * @param key - 要导出的公钥
 * @returns Promise<Uint8Array> 公钥的原始字节
 */
export async function exportPublicKey(key: CryptoKey): Promise<Uint8Array> {
  try {
    const exported = await crypto.subtle.exportKey('raw', key);
    return new Uint8Array(exported);
  } catch (e) {
    throw new CryptoError(`导出公钥失败: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * 从原始字节导入公钥
 *
 * @param bytes - 公钥的原始字节（SEC1 格式）
 * @returns Promise<CryptoKey> 导入的公钥
 */
export async function importPublicKey(bytes: Uint8Array): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(
      'raw',
      bytes.buffer as ArrayBuffer,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
  } catch (e) {
    throw new CryptoError(`导入公钥失败: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * 使用 ECDH 派生共享密钥
 *
 * @param privateKey - 我方的私钥
 * @param peerPublicKey - 对方的公钥
 * @returns Promise<CryptoKey> 派生的共享密钥（AES-GCM 密钥）
 */
export async function deriveSharedKey(
  privateKey: CryptoKey,
  peerPublicKey: CryptoKey
): Promise<CryptoKey> {
  try {
    // 直接派生 AES-GCM 密钥
    return await crypto.subtle.deriveKey(
      {
        name: 'ECDH',
        public: peerPublicKey,
      },
      privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  } catch (e) {
    throw new CryptoError(`派生共享密钥失败: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * 加密数据
 *
 * @param data - 要加密的数据（字符串或字节数组）
 * @param key - 共享密钥
 * @returns Promise<Uint8Array> 加密后的数据（包含 nonce 和密文）
 */
export async function encrypt(
  data: string | Uint8Array,
  key: CryptoKey
): Promise<Uint8Array> {
  try {
    // 生成随机 nonce（96 位）
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    // 将字符串转换为字节数组
    const plaintext = typeof data === 'string'
      ? new TextEncoder().encode(data)
      : data;

    // 加密
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      plaintext as BufferSource
    );

    // 组合 nonce + ciphertext
    const result = new Uint8Array(nonce.length + ciphertext.byteLength);
    result.set(nonce, 0);
    result.set(new Uint8Array(ciphertext), nonce.length);

    return result;
  } catch (e) {
    throw new CryptoError(`加密失败: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * 解密数据
 *
 * @param data - 加密数据（包含 nonce 和密文）
 * @param key - 共享密钥
 * @returns Promise<Uint8Array> 解密后的字节数组
 */
export async function decrypt(
  data: Uint8Array,
  key: CryptoKey
): Promise<Uint8Array> {
  try {
    if (data.length < 12) {
      throw new CryptoError('加密数据过短');
    }

    // 分离 nonce 和密文
    const nonce = data.slice(0, 12);
    const ciphertext = data.slice(12);

    // 解密
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      ciphertext
    );

    return new Uint8Array(plaintext);
  } catch (e) {
    throw new CryptoError(`解密失败: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * 加密字符串并返回 Base64
 *
 * @param plaintext - 要加密的字符串
 * @param key - 共享密钥
 * @returns Promise<string> Base64 编码的加密数据
 */
export async function encryptString(plaintext: string, key: CryptoKey): Promise<string> {
  const data = await encrypt(plaintext, key);
  // 使用 base64 编码
  const binary = String.fromCharCode(...data);
  return btoa(binary);
}

/**
 * 从 Base64 解密为字符串
 *
 * @param ciphertextB64 - Base64 编码的加密数据
 * @param key - 共享密钥
 * @returns Promise<string> 解密后的字符串
 */
export async function decryptString(ciphertextB64: string, key: CryptoKey): Promise<string> {
  // 解码 base64
  const binary = atob(ciphertextB64);
  const data = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    data[i] = binary.charCodeAt(i);
  }

  const decrypted = await decrypt(data, key);
  return new TextDecoder().decode(decrypted);
}

/**
 * 将 Uint8Array 转换为十六进制字符串（用于调试）
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * 将十六进制字符串转换为 Uint8Array（用于调试）
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
