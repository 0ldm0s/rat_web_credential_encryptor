# rat-web-credential-encryptor

JavaScript 加密库，与 `rat_web_credential_encryptor` Rust 库配合使用。

## 功能特性

- **ECDH P-256 密钥交换**：使用浏览器原生 Web Crypto API
- **AES-256-GCM 加密**：认证加密，防篡改
- **跨平台兼容**：纯 JavaScript 实现，支持所有现代浏览器

## 安装

```bash
npm install rat-web-credential-encryptor
```

## API

### 密钥生成

```typescript
import { generateKeyPair } from 'rat-web-credential-encryptor';

const { privateKey, publicKey } = await generateKeyPair();
```

### 公钥导入/导出

```typescript
import { exportPublicKey, importPublicKey } from 'rat-web-credential-encryptor';

// 导出公钥为字节数组
const pubKeyBytes = await exportPublicKey(publicKey);

// 从字节数组导入公钥
const importedPubKey = await importPublicKey(pubKeyBytes);
```

### ECDH 密钥交换

```typescript
import { deriveSharedKey } from 'rat-web-credential-encryptor';

// 使用我方私钥和对方公钥派生共享密钥
const sharedKey = await deriveSharedKey(privateKey, peerPublicKey);
```

### 加密/解密

```typescript
import { encrypt, decrypt, encryptString, decryptString } from 'rat-web-credential-encryptor';

// 加密/解密字节数组
const encrypted = await encrypt(plaintext, sharedKey);
const decrypted = await decrypt(encrypted, sharedKey);

// 加密/解密字符串（返回/接受 Base64）
const ciphertext = await encryptString('敏感数据', sharedKey);
const decrypted = await decryptString(ciphertext, sharedKey);
```

## 完整示例

```typescript
import {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  deriveSharedKey,
  encryptString,
  decryptString,
} from 'rat-web-credential-encryptor';

// 1. 前端生成密钥对
const { privateKey, publicKey } = await generateKeyPair();

// 2. 导出公钥发送给后端
const pubKeyBytes = await exportPublicKey(publicKey);
// fetch('/api/register', {
//   method: 'POST',
//   body: JSON.stringify({ publicKey: Array.from(pubKeyBytes) })
// });

// 3. 假设从后端收到公钥
// const serverPubKeyBytes = new Uint8Array(await response.json());
// const serverPubKey = await importPublicKey(serverPubKeyBytes);

// 模拟后端公钥（实际应从服务器获取）
const serverKeyPair = await generateKeyPair();
const serverPubKey = serverKeyPair.publicKey;

// 4. 派生共享密钥
const sharedKey = await deriveSharedKey(privateKey, serverPubKey);

// 5. 加密敏感数据
const password = 'my-secret-password';
const encryptedPassword = await encryptString(password, sharedKey);
console.log('加密后的密码:', encryptedPassword);

// 6. 解密收到的数据
const decrypted = await decryptString(encryptedPassword, sharedKey);
console.log('解密后:', decrypted);
```

## Rust 后端配合

Rust 端使用 `rat_web_credential_encryptor` 库：

```rust
use rat_web_credential_encryptor::{
    generate_keypair, export_public_key, import_public_key,
    derive_shared_secret, encrypt_string, decrypt_string,
};

// 后端生成密钥对
let (server_priv, server_pub) = generate_keypair();

// 导出公钥发送给前端
let server_pub_bytes = export_public_key(&server_pub);

// 导入前端公钥
let client_pub = import_public_key(&client_pub_bytes)?;

// 派生共享密钥
let shared_key = derive_shared_secret(&server_priv, &client_pub)?;

// 加密/解密
let ciphertext = encrypt_string("敏感数据", &shared_key)?;
let decrypted = decrypt_string(&ciphertext, &shared_key)?;
```

## 浏览器兼容性

- Chrome 37+
- Firefox 34+
- Safari 7.1+
- Edge 12+

## License

MIT
