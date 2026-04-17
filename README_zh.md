# react-native-nitro-crypto

使用 [Nitro Modules](https://github.com/mrousavy/react-native-nitro) 和 Rust 为 React Native 实现的高性能 Node.js `crypto` & Web Crypto 库。

本库提供了一个高性能、跨平台的解决方案，包含了 Node.js `crypto` API 和标准 Web Crypto API 的实现，底层由原生 Rust 驱动。它实现了与 Node.js 24 `crypto` 模块 **几乎完全的兼容性**，同时保持了极致的运行效率。

## 🚀 为什么选择 Nitro Crypto?

在 React Native 生态系统中，`react-native-nitro-crypto` 通过结合现代架构与极致兼容性脱颖而出：

| 特性 | Nitro Crypto | Quick Crypto | Expo Crypto |
| :--- | :---: | :---: | :---: |
| **底层引擎** | **Nitro + Rust** | JSI + C++ | 原生 (Java/Swift) |
| **Node.js 24 兼容性** | ✅ **几乎完全支持** | ✅ 部分支持 | ❌ 极少覆盖 |
| **Web Crypto API** | ✅ **完全支持** | ❌ 部分支持 | ❌ 部分支持 |
| **后量子加密 (PQC)** | ✅ **支持** | ❌ 不支持 | ❌ 不支持 |
| **运行性能** | 极高 (Nitro) | 高 (JSI) | 一般 |

## 特性

*   **⚡️ 极致性能**：利用 Nitro Modules 的超低开销，提供接近原生的执行速度。
*   **🔄 Node.js 24 兼容性**：实现了 Node.js 24 `crypto` 模块的 **几乎所有接口**（Hash, HMAC, Cipher, Sign, DiffieHellman 等）。API 签名和参数与 Node.js 严格对齐，无需修改即可运行大多数依赖加密的 Node 库。
*   **🌐 Web Crypto API**：完全支持标准的 Web Crypto API (`crypto.subtle`)，开发体验与现代浏览器无异。
*   **🔐 后量子密码学 (PQC)**：提供对下一代加密算法如 **ML-DSA (Dilithium)** 和 **ML-KEM (Kyber)** 的原生支持。
*   **🦀 现代 Rust 后端**：基于内存安全、高性能的 Rust 核心构建。
*   **📱 跨平台**：为 iOS 和 Android 提供一流的兼容性和性能。

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

*   **哈希 (Hashes)**：SHA-1, SHA-256, SHA-384, SHA-512, MD5, SHA3 系列, RIPEMD (128, 160, 320)。
*   **HMAC**：支持所有哈希算法。
*   **对称加密 (Symmetric)**：AES (CBC, CTR, GCM, KW, OCB), ChaCha20-Poly1305。
*   **非对称加密 (Asymmetric)**：RSA (OAEP, PSS, PKCS1), ECDSA, ECDH。
*   **现代曲线 (Modern Curves)**：Ed25519, X25519, Ed448, X448。
*   **后量子 (Post-Quantum)**：ML-DSA, ML-KEM。
*   **密钥派生 (KDF)**：PBKDF2, HKDF, Scrypt, Argon2。

有关已实现 API 和覆盖率的详细列表，请参阅 [实现覆盖率](./docs/implementation-coverage.md)。

## 许可证

ISC
