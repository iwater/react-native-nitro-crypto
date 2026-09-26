import { Buffer } from 'react-native-nitro-buffer'
import { native } from '../native'
import type { HybridCipher, HybridDecipher } from '../specs/NitroNodeCrypto.nitro'
import { toArrayBuffer } from './utils'

/**
 * Safely convert a Buffer, TypedArray, or ArrayBuffer to a pure ArrayBuffer.
 * This handles cross-module Buffer instances where Buffer.isBuffer() may fail.
 */
function ensureArrayBuffer(input: Buffer | ArrayBuffer | ArrayBufferView | null | undefined): ArrayBuffer {
    // ⚠️ `null` / `undefined` ⇒ **空 ArrayBuffer**：ECB 这类模式本来就没有 IV
    //（node 的 `createCipheriv('aes-128-ecb', key, null)` 是合法的）。
    // 其它模式会被原生的长度校验挡下（与 node 的 ERR_CRYPTO_INVALID_IV 同类）。
    if (input === null || input === undefined) return new ArrayBuffer(0)
    if (input instanceof ArrayBuffer) return input
    if (ArrayBuffer.isView(input)) {
        return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer
    }
    return input as ArrayBuffer
}

// ⚠️ 这个类型是**编译期便利**，不是运行时真值 —— 运行时的 `getCiphers()` 直接问原生侧
// （原生层 的 `SUPPORTED_CIPHERS`，与 `kind_from_name` 同源展开）。
// 改算法时以原生侧那张表为准，这里跟着改（当前 25 个 = 9 + 16）。
export type CipherAlgorithm = 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc' | 'aes-128-ctr' | 'aes-192-ctr' | 'aes-256-ctr' | 'aes-128-gcm' | 'aes-192-gcm' | 'aes-256-gcm'
    // 第 4 条（2026-09-26）：把「实现已有、只是没暴露」的 16 个名字接进来
    | 'aes-128-ocb' | 'aes-192-ocb' | 'aes-256-ocb' | 'chacha20-poly1305'
    | 'aes128-wrap' | 'aes192-wrap' | 'aes256-wrap'
    | 'aes128-wrap-pad' | 'aes192-wrap-pad' | 'aes256-wrap-pad'
    | 'id-aes128-wrap' | 'id-aes192-wrap' | 'id-aes256-wrap'
    | 'id-aes128-wrap-pad' | 'id-aes192-wrap-pad' | 'id-aes256-wrap-pad'
    // 第 5、6 条（2026-09-26）
    | 'aes-128-ecb' | 'aes-192-ecb' | 'aes-256-ecb'
    | 'aes-128-ccm' | 'aes-192-ccm' | 'aes-256-ccm'
    | 'id-aes128-CCM' | 'id-aes192-CCM' | 'id-aes256-CCM'
    | 'aes-128-cfb' | 'aes-192-cfb' | 'aes-256-cfb'
    | 'aes-128-ofb' | 'aes-192-ofb' | 'aes-256-ofb'
    | 'aes-128-xts' | 'aes-256-xts'

function expectedAesKeyLength(algorithm: string): number | null {
    // ⚠️ XTS 的 key 是 **2×**（两个 AES key 拼在一起）—— 实测 node：
    //    `aes-128-xts` keyLength 32、`aes-256-xts` keyLength 64。
    //    按名字里的位数直接推会**误拒**合法的 XTS 调用（本轮踩过）。
    const xts = algorithm.endsWith('-xts')
    if (algorithm.startsWith('aes-128-')) return xts ? 32 : 16
    if (algorithm.startsWith('aes-192-')) return xts ? 48 : 24
    if (algorithm.startsWith('aes-256-')) return xts ? 64 : 32
    return null
}

function validateCipherParams(algorithm: string, keyAb: ArrayBuffer, ivAb: ArrayBuffer): void {
    const keyLen = keyAb.byteLength
    const ivLen = ivAb.byteLength
    const expectedKeyLen = expectedAesKeyLength(algorithm)

    if (expectedKeyLen !== null && keyLen !== expectedKeyLen) {
        throw new Error(`Invalid key length: expected ${expectedKeyLen} bytes, got ${keyLen}`)
    }

    if (algorithm.endsWith('-cbc') || algorithm.endsWith('-ctr')) {
        if (ivLen !== 16) {
            throw new Error(`Invalid IV length for ${algorithm}: expected 16 bytes, got ${ivLen}`)
        }
    } else if (algorithm.endsWith('-gcm')) {
        if (ivLen <= 0) {
            throw new Error(`Invalid IV length for ${algorithm}: expected > 0 bytes, got ${ivLen}`)
        }
    }
}

export class Cipheriv {
    private nativeCipher: HybridCipher

    constructor(algorithm: CipherAlgorithm, key: Buffer | ArrayBuffer, iv: Buffer | ArrayBuffer) {
        const keyAb = ensureArrayBuffer(key)
        const ivAb = ensureArrayBuffer(iv)
        validateCipherParams(algorithm, keyAb, ivAb)
        this.nativeCipher = native.createCipheriv(algorithm, keyAb, ivAb)
    }

    update(data: string | Buffer | ArrayBuffer, inputEncoding?: BufferEncoding, outputEncoding?: 'hex' | 'base64' | 'utf8' | 'utf-8'): Buffer | string {
        const dataAb = toArrayBuffer(data, inputEncoding)
        const resultAb = this.nativeCipher.update(dataAb)
        const resultBuf = Buffer.from(resultAb)

        if (outputEncoding === 'hex') return resultBuf.toString('hex')
        if (outputEncoding === 'base64') return resultBuf.toString('base64')
        if (outputEncoding === 'utf8' || outputEncoding === 'utf-8') return resultBuf.toString('utf8')
        return resultBuf
    }

    final(outputEncoding?: 'hex' | 'base64' | 'utf8' | 'utf-8'): Buffer | string {
        const resultAb = this.nativeCipher.final()
        const resultBuf = Buffer.from(resultAb)

        if (outputEncoding === 'hex') return resultBuf.toString('hex')
        if (outputEncoding === 'base64') return resultBuf.toString('base64')
        if (outputEncoding === 'utf8' || outputEncoding === 'utf-8') return resultBuf.toString('utf8')
        return resultBuf
    }

    setAutoPadding(autoPadding: boolean = true): this {
        this.nativeCipher.setAutoPadding(autoPadding)
        return this
    }

    /**
     * Sets the Additional Authenticated Data (AAD) for AEAD ciphers (GCM, CCM, OCB).
     * Must be called before update().
     */
    setAAD(buffer: Buffer | ArrayBuffer, options?: { plaintextLength?: number }): this {
        const ab = toArrayBuffer(buffer)
        this.nativeCipher.setAAD(ab)
        return this
    }

    /**
     * Returns the authentication tag for AEAD ciphers.
     * Must be called after final() has been called.
     */
    getAuthTag(): Buffer {
        const tagAb = this.nativeCipher.getAuthTag()
        return Buffer.from(tagAb)
    }
}

export class Decipheriv {
    private nativeDecipher: HybridDecipher

    constructor(algorithm: CipherAlgorithm, key: Buffer | ArrayBuffer, iv: Buffer | ArrayBuffer) {
        const keyAb = ensureArrayBuffer(key)
        const ivAb = ensureArrayBuffer(iv)
        validateCipherParams(algorithm, keyAb, ivAb)
        this.nativeDecipher = native.createDecipheriv(algorithm, keyAb, ivAb)
    }

    update(data: string | Buffer | ArrayBuffer, inputEncoding?: BufferEncoding, outputEncoding?: 'hex' | 'base64' | 'utf8' | 'utf-8'): Buffer | string {
        const dataAb = toArrayBuffer(data, inputEncoding)
        const resultAb = this.nativeDecipher.update(dataAb)
        const resultBuf = Buffer.from(resultAb)

        if (outputEncoding === 'hex') return resultBuf.toString('hex')
        if (outputEncoding === 'base64') return resultBuf.toString('base64')
        if (outputEncoding === 'utf8' || outputEncoding === 'utf-8') return resultBuf.toString('utf8')
        return resultBuf
    }

    final(outputEncoding?: 'hex' | 'base64' | 'utf8' | 'utf-8'): Buffer | string {
        const resultAb = this.nativeDecipher.final()
        const resultBuf = Buffer.from(resultAb)

        if (outputEncoding === 'hex') return resultBuf.toString('hex')
        if (outputEncoding === 'base64') return resultBuf.toString('base64')
        if (outputEncoding === 'utf8' || outputEncoding === 'utf-8') return resultBuf.toString('utf8')
        return resultBuf
    }

    setAutoPadding(autoPadding: boolean = true): this {
        this.nativeDecipher.setAutoPadding(autoPadding)
        return this
    }

    /**
     * Sets the Additional Authenticated Data (AAD) for AEAD ciphers (GCM, CCM, OCB).
     * Must be called before update().
     */
    setAAD(buffer: Buffer | ArrayBuffer, options?: { plaintextLength?: number }): this {
        const ab = toArrayBuffer(buffer)
        this.nativeDecipher.setAAD(ab)
        return this
    }

    /**
     * Sets the authentication tag for AEAD decryption.
     * Must be called before final() for GCM mode.
     */
    setAuthTag(buffer: Buffer | ArrayBuffer, encoding?: BufferEncoding): this {
        const ab = toArrayBuffer(buffer)
        this.nativeDecipher.setAuthTag(ab)
        return this
    }
}
