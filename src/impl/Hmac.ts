import { Buffer } from 'react-native-nitro-buffer'
import { native } from '../native'
import { binaryLikeToArrayBuffer, type BinaryLike } from './utils'
import type { KeyObject } from './KeyObject'

export type HmacAlgorithm = string // 'sha256' | 'sha1' | ...

export class Hmac {
    private nativeHmac: any // HybridHmac
    private isFinalized = false

    constructor(private algorithm: HmacAlgorithm, key: BinaryLike | Buffer | ArrayBuffer | KeyObject) {
        let keyBuffer: ArrayBuffer
        if (key && typeof key === 'object' && 'type' in key && (key.type === 'secret' || key.type === 'private' || key.type === 'public')) {
            // KeyObject - export to get the raw key
            const keyObj = key as KeyObject
            const exported = keyObj.export()
            if (typeof exported === 'string') {
                const buf = Buffer.from(exported)
                keyBuffer = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer
            } else if (Buffer.isBuffer(exported)) {
                keyBuffer = exported.buffer.slice(exported.byteOffset, exported.byteOffset + exported.byteLength) as ArrayBuffer
            } else {
                throw new Error('KeyObject cannot be exported for HMAC')
            }
        } else {
            keyBuffer = binaryLikeToArrayBuffer(key as BinaryLike | Buffer | ArrayBuffer)
        }

        // Initialize native HMAC
        this.nativeHmac = native.createHmac(algorithm, keyBuffer)
    }


    update(data: string | Buffer | ArrayBuffer, inputEncoding?: BufferEncoding): this {
        if (this.isFinalized) throw new Error('Digest already called')

        let ab: ArrayBuffer
        if (typeof data === 'string') {
            const buf = Buffer.from(data, inputEncoding || 'utf8')
            ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
        } else if (Buffer.isBuffer(data)) {
            ab = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)
        } else {
            ab = data
        }

        this.nativeHmac.update(ab)
        return this
    }

    digest(): Buffer
    digest(encoding: 'hex' | 'base64'): string
    digest(encoding?: 'hex' | 'base64'): Buffer | string {
        if (this.isFinalized) throw new Error('Digest already called')

        const hashAb = this.nativeHmac.digest()
        this.isFinalized = true // Native object is consumed/invalidated

        const hashBuf = Buffer.from(hashAb)
        if (encoding === 'hex') return hashBuf.toString('hex')
        if (encoding === 'base64') return hashBuf.toString('base64')
        return hashBuf
    }
}

// HKDF Polyfill (RFC 5869)
// Moves here because it relies on Hmac class and we want to avoid circular dependency with index/crypto.
export function hkdfPolyfill(hash: string, ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
    const hashLen = hash === 'sha256' ? 32 : hash === 'sha384' ? 48 : hash === 'sha512' ? 64 : 20 // sha1 = 20

    // Extract
    const prkKey = salt.length === 0 ? Buffer.alloc(hashLen, 0) : salt
    const hmacExtract = new Hmac(hash, prkKey)
    hmacExtract.update(ikm)
    const prk = hmacExtract.digest()

    // Expand
    const n = Math.ceil(length / hashLen)
    const okm: Buffer[] = []
    let prev = Buffer.alloc(0)
    for (let i = 1; i <= n; i++) {
        const hmacExpand = new Hmac(hash, prk)
        hmacExpand.update(prev)
        hmacExpand.update(info)
        hmacExpand.update(Buffer.from([i]))
        prev = hmacExpand.digest() as Buffer
        okm.push(prev)
    }
    return Buffer.concat(okm).slice(0, length)
}
