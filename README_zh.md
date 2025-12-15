# react-native-nitro-crypto

使用 [Nitro Modules](https://github.com/mrousavy/react-native-nitro) 和 Rust 为 React Native 实现的 Node.js `crypto` 模块。

本库提供了一个高性能、跨平台的解决方案，包含了 Node.js `crypto` API 和标准 Web Crypto API 的实现，底层由原生 Rust 驱动。它实现了与 Node.js 24 `crypto` 模块 **几乎完全的兼容性**，实现了 **所有接口** 并保持参数一致。

## 特性

*   **⚡️ 高性能**：基于 Rust 和 Nitro Modules 构建，提供接近原生的性能。
*   **🔄 Node.js 24 兼容性**：实现了 Node.js 24 `crypto` 模块的 **所有接口**。API 签名和参数与 Node.js 严格对齐，这使得您可以在 React Native 中直接使用几乎任何依赖加密功能的 Node.js 库，而无需修改代码。
*   **🌐 Web Crypto API**：完全支持标准的 Web Crypto API (`crypto.subtle`)，与浏览器环境保持一致。
*   **🔐 后量子密码学**：支持下一代算法，如 ML-DSA (Dilithium) 和 ML-KEM (Kyber)。
*   **📱 跨平台**：同时支持 iOS 和 Android。

## 安装

```bash
npm install react-native-nitro-crypto
# 或者
yarn add react-native-nitro-crypto
```

本库依赖 `react-native-nitro-modules`，请确保您的项目已正确配置该模块。

## 使用方法

### Node.js Crypto API

您可以将 `react-native-nitro-crypto` 作为 polyfill 引入，或者直接使用它。

```typescript
import crypto from 'react-native-nitro-crypto';

// 哈希
const hash = crypto.createHash('sha256');
hash.update('Hello World');
console.log(hash.digest('hex'));

// HMAC
const hmac = crypto.createHmac('sha256', 'secret-key');
hmac.update('data to sign');
console.log(hmac.digest('hex'));

// 随机字节
const random = crypto.randomBytes(16);
console.log(random.toString('hex'));
```

### Web Crypto API

Web Crypto API 可通过 `crypto.subtle` 或 `crypto.webcrypto.subtle` 访问。

```typescript
import { webcrypto } from 'react-native-nitro-crypto';

async function signMessage() {
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"]
  );

  const data = new TextEncoder().encode("Hello World");
  const signature = await webcrypto.subtle.sign(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    keyPair.privateKey,
    data
  );

  console.log(new Uint8Array(signature));
}
```

## 支持的算法

本库支持广泛的算法，包括：

*   **哈希 (Hashes)**：SHA-1, SHA-256, SHA-384, SHA-512, MD5, SHA3 系列。
*   **HMAC**：支持所有哈希算法。
*   **对称加密 (Symmetric)**：AES (CBC, CTR, GCM, KW, OCB), ChaCha20-Poly1305。
*   **非对称加密 (Asymmetric)**：RSA (OAEP, PSS, PKCS1), ECDSA, ECDH。
*   **现代曲线 (Modern Curves)**：Ed25519, X25519, Ed448, X448。
*   **后量子 (Post-Quantum)**：ML-DSA, ML-KEM。
*   **密钥派生 (KDF)**：PBKDF2, HKDF, Scrypt, Argon2。

有关已实现 API 和覆盖率的详细列表，请参阅 [实现覆盖率](./docs/implementation-coverage.md)。

## 许可证

ISC
