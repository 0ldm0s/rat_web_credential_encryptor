/**
 * JavaScript 端加密测试
 */

import {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  deriveSharedKey,
  encrypt,
  decrypt,
  encryptString,
  decryptString,
} from '../src/index.js';

// 测试密钥生成
await (async function testGenerateKeyPair() {
  console.log('测试密钥生成...');
  const keyPair = await generateKeyPair();
  console.assert(keyPair.privateKey !== null, '私钥存在');
  console.assert(keyPair.publicKey !== null, '公钥存在');
  console.log('✓ 密钥生成测试通过');
})();

// 测试公钥导出/导入往返
await (async function testExportImportRoundtrip() {
  console.log('测试公钥导出/导入...');
  const keyPair = await generateKeyPair();
  const exported = await exportPublicKey(keyPair.publicKey);
  const imported = await importPublicKey(exported);

  // 验证导入的公钥可以用于派生密钥
  const testKeyPair = await generateKeyPair();
  const derived1 = await deriveSharedKey(testKeyPair.privateKey, keyPair.publicKey);
  const derived2 = await deriveSharedKey(testKeyPair.privateKey, imported);

  console.assert(derived1 !== null, '导出前可派生');
  console.assert(derived2 !== null, '导入后可派生');
  console.log('✓ 公钥导出/导入测试通过');
})();

// 测试 ECDH 密钥交换
await (async function testEcdh() {
  console.log('测试 ECDH 密钥交换...');
  const alice = await generateKeyPair();
  const bob = await generateKeyPair();

  // Alice 使用 Bob 的公钥派生密钥
  const aliceShared = await deriveSharedKey(alice.privateKey, bob.publicKey);

  // Bob 使用 Alice 的公钥派生密钥
  const bobShared = await deriveSharedKey(bob.privateKey, alice.publicKey);

  // 验证密钥相同（通过加密/解密测试）
  const plaintext = 'test data';
  const encrypted = await encrypt(plaintext, aliceShared);
  const decrypted = await decrypt(encrypted, bobShared);
  const decoded = new TextDecoder().decode(decrypted);

  console.assert(decoded === plaintext, 'ECDH 派生密钥一致');
  console.log('✓ ECDH 密钥交换测试通过');
})();

// 测试加密/解密
await (async function testEncryptDecrypt() {
  console.log('测试加密/解密...');
  const keyPair = await generateKeyPair();
  const testKeyPair = await generateKeyPair();
  const sharedKey = await deriveSharedKey(keyPair.privateKey, testKeyPair.publicKey);

  const plaintext = 'Hello, World!';
  const encrypted = await encrypt(plaintext, sharedKey);
  const decrypted = await decrypt(encrypted, sharedKey);
  const decoded = new TextDecoder().decode(decrypted);

  console.assert(decoded === plaintext, '加密/解密正确');
  console.log('✓ 加密/解密测试通过');
})();

// 测试字符串加密/解密
await (async function testEncryptString() {
  console.log('测试字符串加密/解密...');
  const keyPair = await generateKeyPair();
  const testKeyPair = await generateKeyPair();
  const sharedKey = await deriveSharedKey(keyPair.privateKey, testKeyPair.publicKey);

  const plaintext = '敏感密码123!@#';
  const ciphertext = await encryptString(plaintext, sharedKey);
  const decrypted = await decryptString(ciphertext, sharedKey);

  console.assert(decrypted === plaintext, '字符串加密/解密正确');
  console.log('✓ 字符串加密/解密测试通过');
})();

// 测试错误密钥
await (async function testWrongKey() {
  console.log('测试错误密钥...');
  const keyPair1 = await generateKeyPair();
  const keyPair2 = await generateKeyPair();
  const keyPair3 = await generateKeyPair();

  const sharedKey1 = await deriveSharedKey(keyPair1.privateKey, keyPair2.publicKey);
  const sharedKey2 = await deriveSharedKey(keyPair2.privateKey, keyPair3.publicKey);

  const plaintext = 'secret data';
  const encrypted = await encrypt(plaintext, sharedKey1);

  try {
    await decrypt(encrypted, sharedKey2);
    console.assert(false, '应该抛出错误');
  } catch {
    console.log('✓ 错误密钥测试通过');
  }
})();

// 测试空数据
await (async function testEmptyData() {
  console.log('测试空数据...');
  const keyPair = await generateKeyPair();
  const testKeyPair = await generateKeyPair();
  const sharedKey = await deriveSharedKey(keyPair.privateKey, testKeyPair.publicKey);

  const plaintext = '';
  const encrypted = await encrypt(plaintext, sharedKey);
  const decrypted = await decrypt(encrypted, sharedKey);
  const decoded = new TextDecoder().decode(decrypted);

  console.assert(decoded === plaintext, '空数据加密/解密正确');
  console.log('✓ 空数据测试通过');
})();

// 测试长数据
await (async function testLongData() {
  console.log('测试长数据...');
  const keyPair = await generateKeyPair();
  const testKeyPair = await generateKeyPair();
  const sharedKey = await deriveSharedKey(keyPair.privateKey, testKeyPair.publicKey);

  const plaintext = 'x'.repeat(10000);
  const encrypted = await encrypt(plaintext, sharedKey);
  const decrypted = await decrypt(encrypted, sharedKey);
  const decoded = new TextDecoder().decode(decrypted);

  console.assert(decoded === plaintext, '长数据加密/解密正确');
  console.log('✓ 长数据测试通过');
})();

console.log('\n所有测试通过！');
