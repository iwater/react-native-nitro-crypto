import { Buffer } from '@craftzdog/react-native-buffer'

/**
 * Node.js compatible BinaryLike type
 * Represents data that can be used as input for cryptographic operations
 */
export type BinaryLike = string | ArrayBufferView

/**
 * Node.js compatible Encoding types
 */
export type BinaryToTextEncoding = 'base64' | 'base64url' | 'hex' | 'binary'
export type CharacterEncoding = 'utf8' | 'utf-8' | 'utf16le' | 'utf-16le' | 'latin1'
export type LegacyCharacterEncoding = 'ascii' | 'binary' | 'ucs2' | 'ucs-2'
export type Encoding = BinaryToTextEncoding | CharacterEncoding | LegacyCharacterEncoding

/**
 * Convert BinaryLike to ArrayBuffer
 */
export function binaryLikeToArrayBuffer(data: BinaryLike | Buffer | ArrayBuffer, encoding?: BufferEncoding): ArrayBuffer {
    if (typeof data === 'string') {
        const buf = Buffer.from(data, encoding || 'utf8')
        return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer
    } else if (Buffer.isBuffer(data)) {
        return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer
    } else if (ArrayBuffer.isView(data)) {
        return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer
    } else if (data instanceof ArrayBuffer) {
        return data
    }
    return data as ArrayBuffer
}

export function toArrayBuffer(data: string | Buffer | ArrayBuffer | ArrayBufferView, encoding?: BufferEncoding): ArrayBuffer {
    if (typeof data === 'string') {
        const buf = Buffer.from(data, encoding || 'utf8')
        return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer
    } else if (Buffer.isBuffer(data)) {
        return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer
    } else if (ArrayBuffer.isView(data)) {
        return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer
    } else {
        return data
    }
}

export function prepareBuffer(buffer: Buffer | ArrayBuffer | ArrayBufferView | string): ArrayBuffer {
    if (typeof buffer === 'string') return toArrayBuffer(Buffer.from(buffer))
    if (buffer instanceof Buffer) return toArrayBuffer(buffer)
    if (buffer instanceof ArrayBuffer) return buffer
    // ArrayBufferView (Uint8Array, DataView, etc.)
    if (ArrayBuffer.isView(buffer)) {
        return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength) as ArrayBuffer
    }
    return buffer as ArrayBuffer
}

/**
 * Encode a buffer to base64url format (RFC 4648 Section 5)
 */
export function base64UrlEncode(buffer: Buffer | Uint8Array): string {
    const b = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer)
    return b.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '')
}

/**
 * Decode a base64url string to Buffer
 */
export function base64UrlDecode(str: string): Buffer {
    let s = str.replace(/-/g, '+').replace(/_/g, '/')
    while (s.length % 4) s += '='
    return Buffer.from(s, 'base64')
}

/**
 * JSON Web Key interface (RFC 7517)
 */
export interface JsonWebKey {
    kty: string              // Key Type: "oct", "RSA", "EC", "OKP"
    alg?: string             // Algorithm
    use?: string             // Key Use: "sig", "enc"
    key_ops?: string[]       // Key Operations
    ext?: boolean            // Extractable
    // Symmetric key (oct)
    k?: string               // Key Value (base64url)
    // RSA
    n?: string               // Modulus
    e?: string               // Public Exponent
    d?: string               // Private Exponent
    p?: string               // First Prime Factor
    q?: string               // Second Prime Factor
    dp?: string              // First Factor CRT Exponent
    dq?: string              // Second Factor CRT Exponent
    qi?: string              // First CRT Coefficient
    // EC / OKP
    crv?: string             // Curve name
    x?: string               // X Coordinate
    y?: string               // Y Coordinate (EC only, not for OKP)
}

/**
 * Get JWK algorithm identifier from CryptoKey algorithm
 */
export function getJwkAlg(algorithm: any): string | undefined {
    const name = (algorithm.name || '').toUpperCase()
    const hash = algorithm.hash?.name || algorithm.hash || ''
    const hashUpper = hash.toUpperCase().replace('-', '')

    if (name === 'HMAC') {
        if (hashUpper === 'SHA256') return 'HS256'
        if (hashUpper === 'SHA384') return 'HS384'
        if (hashUpper === 'SHA512') return 'HS512'
        return undefined
    }
    if (name.startsWith('AES')) {
        const keyLen = algorithm.length || 256
        if (name === 'AES-GCM') return `A${keyLen}GCM`
        if (name === 'AES-CBC') return `A${keyLen}CBC`
        if (name === 'AES-KW') return `A${keyLen}KW`
        if (name === 'AES-CTR') return `A${keyLen}CTR`
        return undefined
    }
    if (name === 'RSASSA-PKCS1-V1_5') {
        if (hashUpper === 'SHA256') return 'RS256'
        if (hashUpper === 'SHA384') return 'RS384'
        if (hashUpper === 'SHA512') return 'RS512'
        return undefined
    }
    if (name === 'RSA-PSS') {
        if (hashUpper === 'SHA256') return 'PS256'
        if (hashUpper === 'SHA384') return 'PS384'
        if (hashUpper === 'SHA512') return 'PS512'
        return undefined
    }
    if (name === 'RSA-OAEP') {
        if (hashUpper === 'SHA1' || hashUpper === 'SHA-1') return 'RSA-OAEP'
        if (hashUpper === 'SHA256') return 'RSA-OAEP-256'
        if (hashUpper === 'SHA384') return 'RSA-OAEP-384'
        if (hashUpper === 'SHA512') return 'RSA-OAEP-512'
        return undefined
    }
    if (name === 'ECDSA') {
        const crv = algorithm.namedCurve || ''
        if (crv === 'P-256') return 'ES256'
        if (crv === 'P-384') return 'ES384'
        if (crv === 'P-521') return 'ES512'
        return undefined
    }
    if (name === 'ED25519') return 'EdDSA'
    if (name === 'ED448') return 'EdDSA'
    if (name === 'X25519') return 'ECDH-ES'
    if (name === 'X448') return 'ECDH-ES'
    return undefined
}
