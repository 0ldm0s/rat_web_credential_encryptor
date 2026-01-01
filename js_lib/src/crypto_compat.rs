/**
 * AES-256-GCM 加密/解密（与 Rust 兼容）
 *
 * 格式: nonce(12) + authTag(16) + ciphertext
 */

const ALGORITHM = {
  ECDH: { name: 'ECDH', namedCurve: 'P-256' },
  AES_GCM: { name: 'AES-GCM', length: 256 },
} as const;

const NONCE_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

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
 * 使用 AES-256-GCM 加密数据
 *
 * @param data - 要加密的数据（字符串或字节数组）
 * @param key - 共享密钥（32字节）
 * @returns Uint8Array 加密后的数据（nonce + authTag + ciphertext）
 */
export async function encrypt(
  data: string | Uint8Array,
  key: Uint8Array
): Promise<Uint8Array> {
  try {
    // 生成随机 nonce（96 位）
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));

    // 导入密钥
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    // 将字符串转换为字节数组
    const plaintext = typeof data === 'string'
      ? new TextEncoder().encode(data)
      : data;

    // 加密
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      cryptoKey,
      plaintext as BufferSource
    );

    // 获取 authTag（需要用不同的方法）
    // 使用 encrypt 返回的 ArrayBuffer 后 16 字节是 authTag
    const encryptedArray = new Uint8Array(ciphertext);
    const authTag = encryptedArray.slice(-AUTH_TAG_LENGTH);
    const actualCiphertext = encryptedArray.slice(0, -AUTH_TAG_LENGTH);

    // 组合: nonce(12) + authTag(16) + ciphertext
    const result = new Uint8Array(NONCE_LENGTH + AUTH_TAG_LENGTH + actualCiphertext.length);
    result.set(nonce, 0);
    result.set(authTag, NONCE_LENGTH);
    result.set(actualCiphertext, NONCE_LENGTH + AUTH_TAG_LENGTH);

    return result;
  } catch (e) {
    throw new CryptoError(`加密失败: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * 使用 AES-256-GCM 解密数据
 *
 * @param data - 加密数据（包含 nonce 和 authTag）
 * @param key - 共享密钥（32字节）
 * @returns Uint8Array 解密后的字节数组
 */
export async function decrypt(
  data: Uint8Array,
  key: Uint8Array
): Promise<Uint8Array> {
  try {
    if (data.length < NONCE_LENGTH + AUTH_TAG_LENGTH) {
      throw new CryptoError('加密数据过短');
    }

    // 分离 nonce、authTag 和密文
    const nonce = data.slice(0, NONCE_LENGTH);
    const authTag = data.slice(NONCE_LENGTH, NONCE_LENGTH + AUTH_TAG_LENGTH);
    const ciphertext = data.slice(NONCE_LENGTH + AUTH_TAG_LENGTH);

    // 导入密钥
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    // 组合 authTag + ciphertext 作为加密数据
    const encryptedData = new Uint8Array(AUTH_TAG_LENGTH + ciphertext.length);
    encryptedData.set(authTag, 0);
    encryptedData.set(ciphertext, AUTH_TAG_LENGTH);

    // 解密
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      cryptoKey,
      encryptedData
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
 * @param key - 共享密钥（32字节）
 * @returns Promise<string> Base64 编码的加密数据
 */
export async function encryptString(plaintext: string, key: Uint8Array): Promise<string> {
  const data = await encrypt(plaintext, key);
  // 使用 base64 编码
  const binary = String.fromCharCode(...data);
  return btoa(binary);
}

/**
 * 从 Base64 解密为字符串
 *
 * @param ciphertextB64 - Base64 编码的加密数据
 * @param key - 共享密钥（32字节）
 * @returns Promise<string> 解密后的字符串
 */
export async function decryptString(ciphertextB64: string, key: Uint8Array): Promise<string> {
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
 * 生成随机 32 字节密钥
 */
export function generateKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * 将 Uint8Array 转换为十六进制字符串
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * 将十六进制字符串转换为 Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
