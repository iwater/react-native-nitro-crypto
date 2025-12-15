# react-native-nitro-crypto

Node.js `crypto` implementation for React Native using [Nitro Modules](https://github.com/mrousavy/react-native-nitro) and Rust.

This library provides a high-performance, cross-platform implementation of both the Node.js `crypto` API and the standard Web Crypto API, powered by a native Rust backend. It achieves **almost complete compatibility** with the Node.js 24 `crypto` module, implementing **all interfaces** with matching parameters.

## Features

*   **⚡️ High Performance**: Built with Rust and Nitro Modules for near-native performance.
*   **🔄 Node.js 24 Compatibility**: Implements **all interfaces** of the Node.js 24 `crypto` module. API signatures and parameters are rigorously aligned with Node.js, allowing you to use almost any crypto-dependent Node.js library in React Native without modification.
*   **🌐 Web Crypto API**: Full support for the standard Web Crypto API (`crypto.subtle`), identical to the browser environment.
*   **🔐 Post-Quantum Cryptography**: Includes support for next-generation algorithms like ML-DSA (Dilithium) and ML-KEM (Kyber).
*   **📱 Cross-Platform**: Works on both iOS and Android.

## Installation

```bash
npm install react-native-nitro-crypto
# or
yarn add react-native-nitro-crypto
```

Dependent on `react-native-nitro-modules`, make sure it is properly configured in your project.

## Usage

### Node.js Crypto API

You can import `react-native-nitro-crypto` as a polyfill or use it directly.

```typescript
import crypto from 'react-native-nitro-crypto';

// Hashing
const hash = crypto.createHash('sha256');
hash.update('Hello World');
console.log(hash.digest('hex'));

// HMAC
const hmac = crypto.createHmac('sha256', 'secret-key');
hmac.update('data to sign');
console.log(hmac.digest('hex'));

// Random Bytes
const random = crypto.randomBytes(16);
console.log(random.toString('hex'));
```

### Web Crypto API

The Web Crypto API is available under `crypto.subtle` or `crypto.webcrypto.subtle`.

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

## Supported Algorithms

This library supports a wide range of algorithms, including:

*   **Hashes**: SHA-1, SHA-256, SHA-384, SHA-512, MD5, SHA3 family.
*   **HMAC**: All supported hash algorithms.
*   **Symmetric**: AES (CBC, CTR, GCM, KW, OCB), ChaCha20-Poly1305.
*   **Asymmetric**: RSA (OAEP, PSS, PKCS1), ECDSA, ECDH.
*   **Modern Curves**: Ed25519, X25519, Ed448, X448.
*   **Post-Quantum**: ML-DSA, ML-KEM.
*   **KDF**: PBKDF2, HKDF, Scrypt, Argon2.

For a detailed list of implemented APIs and coverage status, please refer to [Implementation Coverage](./docs/implementation-coverage.md).

## License

ISC
