import { Buffer } from 'react-native-nitro-buffer'
import { native } from '../native'
import type { HybridCipher, HybridDecipher } from '../specs/NitroNodeCrypto.nitro'
import { toArrayBuffer } from './utils'

/**
 * Safely convert a Buffer, TypedArray, or ArrayBuffer to a pure ArrayBuffer.
 * This handles cross-module Buffer instances where Buffer.isBuffer() may fail.
 */
function ensureArrayBuffer(input: Buffer | ArrayBuffer | ArrayBufferView): ArrayBuffer {
    if (input instanceof ArrayBuffer) return input
    if (ArrayBuffer.isView(input)) {
        return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer
    }
    return input as ArrayBuffer
}

export type CipherAlgorithm = 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc' | 'aes-128-ctr' | 'aes-192-ctr' | 'aes-256-ctr' | 'aes-128-gcm' | 'aes-256-gcm'

export class Cipheriv {
    private nativeCipher: HybridCipher

    constructor(algorithm: CipherAlgorithm, key: Buffer | ArrayBuffer, iv: Buffer | ArrayBuffer) {
        const keyAb = ensureArrayBuffer(key)
        const ivAb = ensureArrayBuffer(iv)
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
        const ab = Buffer.isBuffer(buffer) ? buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength) : buffer
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
        const ab = Buffer.isBuffer(buffer) ? buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength) : buffer
        this.nativeDecipher.setAAD(ab)
        return this
    }

    /**
     * Sets the authentication tag for AEAD decryption.
     * Must be called before final() for GCM mode.
     */
    setAuthTag(buffer: Buffer | ArrayBuffer, encoding?: BufferEncoding): this {
        const ab = Buffer.isBuffer(buffer) ? buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength) : buffer
        this.nativeDecipher.setAuthTag(ab)
        return this
    }
}
