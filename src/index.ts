import { Buffer } from 'react-native-nitro-buffer'
import {
    Hash,
    HashAlgorithm
} from './impl/Hash'
import {
    Hmac,
    HmacAlgorithm,
    hkdfPolyfill
} from './impl/Hmac'
import {
    DiffieHellman,
    DH_GROUPS
} from './impl/DiffieHellman'
import {
    Cipheriv,
    Decipheriv,
    CipherAlgorithm
} from './impl/Cipheriv'
import {
    Sign,
    Verify,
    SignAlgorithm
} from './impl/Sign'
import {
    ECDH
} from './impl/ECDH'
import {
    Certificate
} from './impl/Certificate'
import {
    X509Certificate
} from './impl/X509Certificate'
import {
    KeyObject,
    KeyType,
    KeyObjectType,
    createSecretKey,
    createPublicKey,
    createPrivateKey,
    generateKeyPairSync
} from './impl/KeyObject'
import {
    CryptoKey,
    BufferSource
} from './impl/CryptoKey'
import {
    SubtleCrypto
} from './impl/SubtleCrypto'
import {
    randomBytes,
    randomFillSync,
    randomFill,
    randomInt,
    randomUUID,
    getRandomValues,
    scrypt,
    scryptSync,
    argon2,
    argon2Sync,
    generatePrime,
    generatePrimeSync,
    checkPrime,
    checkPrimeSync,
    secureHeapUsed
} from './impl/random'
import {
    pbkdf2,
    pbkdf2Sync
} from './impl/pbkdf2'
import {
    createCipher,
    createDecipher
} from './impl/legacy'
import {
    constants
} from './impl/constants'
import {
    prepareBuffer,
    toArrayBuffer,
    JsonWebKey,
    BinaryLike,
} from './impl/utils'
import { native } from './native'

// Re-export types
export type {
    HashAlgorithm,
    HmacAlgorithm,
    CipherAlgorithm,
    KeyType,
    KeyObjectType,
    JsonWebKey,
    BufferSource
}
export interface CryptoKeyPair {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
}

export type PublicKeyInput = string | Buffer | KeyObject | {
    key: string | Buffer | KeyObject;
    format?: 'pem' | 'der' | 'jwk';
    type?: 'pkcs1' | 'spki' | 'pkcs8' | 'sec1';
}

export type PrivateKeyInput = string | Buffer | KeyObject | {
    key: string | Buffer | KeyObject;
    format?: 'pem' | 'der' | 'jwk';
    type?: 'pkcs1' | 'spki' | 'pkcs8' | 'sec1';
    passphrase?: string | Buffer;
}

// Re-export classes
export {
    Hash,
    Hmac,
    DiffieHellman,
    Cipheriv,
    Decipheriv,
    Sign,
    Verify,
    ECDH,
    Certificate,
    X509Certificate,
    KeyObject,
    CryptoKey,
    SubtleCrypto
}

// Re-export random functions
export {
    randomBytes,
    randomFillSync,
    randomFill,
    randomInt,
    randomUUID,
    getRandomValues,
    scrypt,
    scryptSync,
    argon2,
    argon2Sync,
    pbkdf2,
    pbkdf2Sync,
    createCipher,
    createDecipher,
    generatePrime,
    generatePrimeSync,
    checkPrime,
    checkPrimeSync,
    secureHeapUsed
}

// Re-export constants
export { constants }

// Helper factory functions for crypto object
export function createHash(algorithm: string, options?: { outputLength?: number }): Hash & any {
    return new Hash(algorithm.toLowerCase() as HashAlgorithm, options)
}

export function createHmac(algorithm: string, key: BinaryLike | Buffer | ArrayBuffer | KeyObject, options?: any): Hmac & any {
    return new Hmac(algorithm.toLowerCase() as HmacAlgorithm, key)
}

export function createDiffieHellman(prime: string | Buffer | ArrayBuffer | number, generator: string | Buffer | ArrayBuffer | number = 2): DiffieHellman {
    if (typeof prime === 'number') {
        return new DiffieHellman(prime, generator)
    }
    return new DiffieHellman(prime, generator)
}

export function createDiffieHellmanGroup(name: string): DiffieHellman {
    const group = DH_GROUPS[name]
    if (!group) throw new Error(`Unknown Diffie-Hellman group: ${name}`)
    return new DiffieHellman(group.prime, group.generator)
}

export function getDiffieHellman(groupName: string): DiffieHellman {
    return createDiffieHellmanGroup(groupName)
}

/**
 * Modern diffieHellman function (Node.js 13.9.0+).
 * Computes a shared secret using the given privateKey and publicKey.
 * Both keys must have the same asymmetricKeyType.
 */
export function diffieHellman(options: { privateKey: KeyObject; publicKey: KeyObject }, callback?: (err: Error | null, secret: Buffer) => void): Buffer | void {
    const { privateKey, publicKey } = options

    if (!(privateKey instanceof KeyObject) || !(publicKey instanceof KeyObject)) {
        throw new TypeError('privateKey and publicKey must be KeyObject instances')
    }

    if (privateKey.type !== 'private') {
        throw new TypeError('privateKey must be a private key')
    }
    if (publicKey.type !== 'public') {
        throw new TypeError('publicKey must be a public key')
    }

    const privKeyType = privateKey.asymmetricKeyType
    const pubKeyType = publicKey.asymmetricKeyType

    if (privKeyType !== pubKeyType) {
        throw new Error(`Key types must match: privateKey is ${privKeyType}, publicKey is ${pubKeyType}`)
    }

    let secret: Buffer

    if (privKeyType === 'x25519' || privKeyType === 'x448' || privKeyType === 'ec' || privKeyType === 'dh') {
        // Use native dhComputeSecretFromKeys for X25519/X448/EC/DH
        const secretAb = native.dhComputeSecretFromKeys(privateKey.hybridKey, publicKey.hybridKey)
        secret = Buffer.from(secretAb)
    } else {
        throw new Error(`diffieHellman not implemented for key type: ${privKeyType}`)
    }


    if (callback) {
        setTimeout(() => callback(null, secret), 0)
        return
    }
    return secret
}


export function createECDH(curveName: string): ECDH {
    return new ECDH(curveName)
}

export function createCipheriv(algorithm: string, key: Buffer | ArrayBuffer, iv: Buffer | ArrayBuffer): Cipheriv & any {
    return new Cipheriv(algorithm.toLowerCase() as CipherAlgorithm, key, iv)
}

export function createDecipheriv(algorithm: string, key: Buffer | ArrayBuffer, iv: Buffer | ArrayBuffer): Decipheriv & any {
    return new Decipheriv(algorithm.toLowerCase() as CipherAlgorithm, key, iv)
}

export function generateKeySync(type: 'hmac' | 'aes', options: { length: number }): KeyObject {
    if (type === 'hmac') {
        const length = options.length || 256 // default
        const key = randomBytes(length / 8)
        return createSecretKey(key)
    }
    if (type === 'aes') {
        const length = options.length
        if (length !== 128 && length !== 192 && length !== 256) throw new Error('Invalid AES key length')
        const key = randomBytes(length / 8)
        return createSecretKey(key)
    }
    throw new Error(`generateKeySync not implemented for ${type}`)
}

// Re-export generateKeyPairSync
export { generateKeyPairSync }

// Async wrappers (simplified, as mostly sync in native currently)
export function generateKey(type: 'hmac' | 'aes', options: { length: number }, callback: (err: Error | null, key: KeyObject) => void): void {
    setTimeout(() => {
        try {
            const key = generateKeySync(type, options)
            callback(null, key)
        } catch (e) {
            callback(e as Error, null as any)
        }
    }, 0)
}

export function generateKeyPair(type: 'rsa' | 'ec' | 'ed25519' | 'ed448' | 'x25519' | 'x448' | 'dsa' | 'rsa-pss', options: any, callback: (err: Error | null, publicKey: any, privateKey: any) => void): void {
    setTimeout(() => {
        try {
            const res = generateKeyPairSync(type, options)
            callback(null, res.publicKey, res.privateKey)
        } catch (e) {
            callback(e as Error, null as any, null as any)
        }
    }, 0)
}

// Add promisify custom symbol for Node.js compatibility
export namespace generateKeyPair {
    export const __promisify__: any = (type: any, options: any) => {
        return new Promise((resolve, reject) => {
            generateKeyPair(type, options, (err, publicKey, privateKey) => {
                if (err) reject(err)
                else resolve({ publicKey, privateKey })
            })
        })
    }
}

export function createSign(algorithm: string): Sign & any {
    return new Sign(algorithm.toLowerCase() as SignAlgorithm)
}

export function createVerify(algorithm: string): Verify & any {
    return new Verify(algorithm.toLowerCase() as SignAlgorithm)
}

export function sign(algorithm: string | null | undefined, data: string | Buffer | ArrayBuffer, key: string | Buffer | ArrayBuffer | KeyObject): Buffer
export function sign(algorithm: string | null | undefined, data: string | Buffer | ArrayBuffer, key: string | Buffer | ArrayBuffer | KeyObject, callback: (err: Error | null, signature: Buffer) => void): void
export function sign(algorithm: string | null | undefined, data: string | Buffer | ArrayBuffer, key: string | Buffer | ArrayBuffer | KeyObject, callback?: (err: Error | null, signature: Buffer) => void): Buffer | void {
    let algo = algorithm
    if (!algo) {
        // Inferred from key? Not really standard behavior but some might expect.
        // Node expects algorithm.
    }

    // Node.js crypto.sign(algorithm, data, key[, callback])
    // or crypto.sign(null, data, key) (if key has algo info?) unfortunately legacy.
    // If we assume algorithm is strictly required string:
    if (typeof algo !== 'string') {
        // Fallback or error
    }

    const signer = new Sign(algo as SignAlgorithm)
    signer.update(data as any)
    const sig = signer.sign(key as any) as Buffer

    if (callback) {
        setTimeout(() => callback(null, sig), 0)
        return
    }
    return sig
}

export function verify(algorithm: string | null | undefined, data: string | Buffer | ArrayBuffer, key: string | Buffer | ArrayBuffer | KeyObject, signature: Buffer | ArrayBuffer): boolean
export function verify(algorithm: string | null | undefined, data: string | Buffer | ArrayBuffer, key: string | Buffer | ArrayBuffer | KeyObject, signature: Buffer | ArrayBuffer, callback: (err: Error | null, result: boolean) => void): void
export function verify(algorithm: string | null | undefined, data: string | Buffer | ArrayBuffer, key: string | Buffer | ArrayBuffer | KeyObject, signature: Buffer | ArrayBuffer, callback?: (err: Error | null, result: boolean) => void): boolean | void {
    const verifier = new Verify(algorithm as SignAlgorithm)
    verifier.update(data as any)
    const res = verifier.verify(key as any, signature)

    if (callback) {
        setTimeout(() => callback(null, res), 0)
        return
    }
    return res
}

export function publicEncrypt(key: PublicKeyInput, buffer: Buffer | ArrayBuffer | Uint8Array): Buffer {
    let keyObj: KeyObject
    let padding = constants.RSA_PKCS1_OAEP_PADDING // Default? Node default is usually OAEP or PKCS1 depending on version.
    // Actually Node default is generic, allows options.

    if (key instanceof KeyObject) {
        keyObj = key
    } else if (typeof key === 'object' && 'key' in key) {
        // extract options
        if (key.key instanceof KeyObject) keyObj = key.key
        else keyObj = createPublicKey(key.key) // simplified
        // handle padding
        // if (key.padding) padding = key.padding
    } else {
        keyObj = createPublicKey(key)
    }

    // Call native directly using hybrid key
    const buf = prepareBuffer(buffer)
    const res = native.publicEncrypt(keyObj.hybridKey, buf, padding)
    return Buffer.from(res)
}

export function privateDecrypt(key: PrivateKeyInput, buffer: Buffer | ArrayBuffer | Uint8Array): Buffer {
    let keyObj: KeyObject
    let padding = constants.RSA_PKCS1_OAEP_PADDING

    if (key instanceof KeyObject) {
        keyObj = key
    } else if (typeof key === 'object' && 'key' in key) {
        if (key.key instanceof KeyObject) keyObj = key.key
        else keyObj = createPrivateKey(key.key)
        // handle padding
    } else {
        keyObj = createPrivateKey(key)
    }

    const buf = prepareBuffer(buffer)
    const res = native.privateDecrypt(keyObj.hybridKey, buf, padding)
    return Buffer.from(res)
}

export function privateEncrypt(key: PrivateKeyInput, buffer: Buffer | ArrayBuffer | Uint8Array): Buffer {
    let keyObj: KeyObject
    let padding = constants.RSA_PKCS1_PADDING // private encrypt usually defaults to pkcs1 (signing)

    if (key instanceof KeyObject) {
        keyObj = key
    } else {
        keyObj = createPrivateKey(key as any) // simplified
    }

    const buf = prepareBuffer(buffer)
    const res = native.privateEncrypt(keyObj.hybridKey, buf, padding)
    return Buffer.from(res)
}

export function publicDecrypt(key: PublicKeyInput, buffer: Buffer | ArrayBuffer | Uint8Array): Buffer {
    let keyObj: KeyObject
    let padding = constants.RSA_PKCS1_PADDING

    if (key instanceof KeyObject) {
        keyObj = key
    } else {
        keyObj = createPublicKey(key as any)
    }

    const buf = prepareBuffer(buffer)
    const res = native.publicDecrypt(keyObj.hybridKey, buf, padding)
    return Buffer.from(res)
}

export function timingSafeEqual(a: Buffer | ArrayBuffer | Uint8Array, b: Buffer | ArrayBuffer | Uint8Array): boolean {
    const bufA = prepareBuffer(a)
    const bufB = prepareBuffer(b)
    if (bufA.byteLength !== bufB.byteLength) return false

    const viewA = new Uint8Array(bufA)
    const viewB = new Uint8Array(bufB)
    let result = 0
    for (let i = 0; i < viewA.length; i++) {
        result |= viewA[i] ^ viewB[i]
    }
    return result === 0
}

function hkdfSync(digest: string, ikm: string | Buffer | ArrayBuffer, salt: string | Buffer | ArrayBuffer, info: string | Buffer | ArrayBuffer, keylen: number): Buffer {
    // Wrapper for polyfill
    const bufIkm = Buffer.from(prepareBuffer(ikm))
    const bufSalt = Buffer.from(prepareBuffer(salt))
    const bufInfo = Buffer.from(prepareBuffer(info))
    return hkdfPolyfill(digest, bufIkm, bufSalt, bufInfo, keylen)
}

export class DiffieHellmanGroup extends DiffieHellman {
    constructor(name: string) {
        const group = DH_GROUPS[name]
        if (!group) throw new Error(`Unknown Diffie-Hellman group: ${name}`)
        super(group.prime, group.generator)
    }
}

// Main crypto object
export const crypto = {
    randomBytes,
    randomFillSync,
    randomFill,
    randomInt,
    randomUUID,
    getRandomValues,
    scrypt,
    scryptSync,
    argon2,
    argon2Sync,
    createHash,
    createHmac,
    createDiffieHellman,
    createDiffieHellmanGroup,
    getDiffieHellman,
    diffieHellman,
    createECDH,
    createCipher,
    createCipheriv,
    createDecipher,
    createDecipheriv,
    createSecretKey,
    createPublicKey,
    createPrivateKey,
    generateKey,
    generateKeySync,
    generateKeyPair,
    generateKeyPairSync,
    generatePrime,
    generatePrimeSync,
    checkPrime,
    checkPrimeSync,
    createSign,
    createVerify,
    sign,
    verify,
    publicEncrypt,
    privateDecrypt,
    privateEncrypt,
    publicDecrypt,
    timingSafeEqual,
    pseudoRandomBytes: randomBytes,
    hkdfSync,
    pbkdf2,
    pbkdf2Sync,
    secureHeapUsed,
    constants,
    Certificate,
    webcrypto: {
        subtle: new SubtleCrypto(),
        getRandomValues,
        randomUUID
    },
    subtle: new SubtleCrypto(), // Alias for webcrypto.subtle
    fips: 0,
    setFips: (bool: boolean) => {
        if (bool) {
            throw new Error('ERR_CRYPTO_FIPS_UNAVAILABLE: FIPS mode is not available')
        }
        // If false, silent success as we are already not in FIPS mode (default)
    },
    getFips: (): 0 | 1 => 0,
    setEngine: (engine: string, flags?: number) => {
        throw new Error('Not supported')
    },
    getCiphers: () => ['aes-128-cbc', 'aes-256-cbc', 'aes-128-gcm', 'aes-256-gcm', 'aes-128-ecb', 'aes-256-ecb'],
    getHashes: () => ['sha1', 'sha256', 'sha384', 'sha512', 'md5'],
    getCurves: () => ['secp256k1', 'p-256', 'p-384', 'p-521', 'curve25519', 'ed25519', 'x25519'],
    hash: (algorithm: string, data: string | Buffer | ArrayBuffer | DataView, outputEncoding?: 'hex' | 'base64' | 'buffer') => {
        const h = createHash(algorithm);
        h.update(data as any);
        if (!outputEncoding || outputEncoding === 'buffer') return h.digest();
        return h.digest(outputEncoding);
    },
    getCipherInfo: (nameOrNid: string | number, options?: any) => {
        // Minimal stub
        return { name: String(nameOrNid), nid: 0, blockSize: 16, ivLength: 16, keyLength: 32, mode: 'cbc' }
    },
    hkdf: (digest: string, ikm: string | Buffer | ArrayBuffer | DataView, salt: string | Buffer | ArrayBuffer | DataView, info: string | Buffer | ArrayBuffer | DataView, keylen: number, callback: (err: Error | null, derivedKey: Buffer) => void) => {
        setTimeout(() => {
            try {
                const res = hkdfSync(digest, ikm as any, salt as any, info as any, keylen)
                callback(null, res)
            } catch (e) {
                callback(e as Error, null as any)
            }
        }, 0)
    },
    // Classes
    Hash,
    Hmac,
    Cipher: Cipheriv,
    Decipher: Decipheriv,
    Cipheriv,
    Decipheriv,
    Sign,
    Verify,
    ECDH,
    DiffieHellman,
    DiffieHellmanGroup,
    X509Certificate,
    KeyObject
}

export const webcrypto = crypto.webcrypto

// Named exports for KeyObject creators and generators (that are NOT already exported as functions)
export {
    createSecretKey,
    createPublicKey,
    createPrivateKey
}

// Named exports for aliases and missing named functions
export const pseudoRandomBytes = randomBytes
export const getFips = crypto.getFips
export const setFips = crypto.setFips
export const getCiphers = crypto.getCiphers
export const getHashes = crypto.getHashes
export const getCurves = crypto.getCurves
export const hash = crypto.hash
export const getCipherInfo = crypto.getCipherInfo
export const hkdf = crypto.hkdf
export { hkdfSync }

// Class aliases
export const fips = 0 // Mock
export const setEngine = crypto.setEngine
export const subtle = crypto.subtle
export const Cipher = Cipheriv
export const Decipher = Decipheriv

// Default export
export default crypto

export { runCompatibilityTests, type TestReport } from './CompatibilityRunner'
