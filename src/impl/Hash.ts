import { Buffer } from 'react-native-nitro-buffer'
import { native } from '../native'

// ⚠️ 这个类型是**编译期便利**，不是运行时真值 —— 运行时的 `getHashes()` 直接问原生侧
// （原生层 的 `SUPPORTED_HASHES`，由该文件的单测保证「声明即可算」）。
// 改算法时以原生侧那张表为准，这里跟着改（当前 22 个）。
export type HashAlgorithm = 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512' | 'sha512-224' | 'sha512-256' | 'md5' | 'sha3-224' | 'sha3-256' | 'sha3-384' | 'sha3-512' | 'shake128' | 'shake256' | 'ripemd128' | 'ripemd160' | 'ripemd320' | 'blake3' | 'blake2b512' | 'blake2s256' | 'sm3' | 'md5-sha1'

export class Hash {
    private chunks: ArrayBuffer[] = []
    private outputLength: number | undefined
    /** 已折到底层的算法名（构造期由 `native.hashBase` 解析）。 */
    private algorithm: HashAlgorithm

    constructor(algorithm: HashAlgorithm, options?: { outputLength?: number }) {
        // ⚠️ 先把 node/OpenSSL 风格的**别名**折到底层再分发：
        //    `RSA-SHA256` → `sha256`、`rmd160` → `ripemd160`、
        //    `id-rsassa-pkcs1-v1_5-with-sha3-256` → `sha3-256` …（共 31 个，实测与底层逐字节相同）
        //    别名表在**原生侧**（原生层 的 `HASH_ALIASES`），
        //    与 `SUPPORTED_HASHES` 一起被单测双向锁住 ⇒ 不可能漂移。
        //    解析不出来的名字**原样返回** ⇒ 下面 switch 的 default 会抛，不会静默算错。
        this.algorithm = native.hashBase(algorithm) as HashAlgorithm
        this.outputLength = options?.outputLength
    }

    update(data: string | Buffer | ArrayBuffer, inputEncoding?: BufferEncoding): this {
        let ab: ArrayBuffer
        if (typeof data === 'string') {
            const buf = Buffer.from(data, inputEncoding || 'utf8')
            ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
        } else if (data instanceof ArrayBuffer) {
            ab = data
        } else if (ArrayBuffer.isView(data)) {
            // Handles Buffer, Uint8Array, and any other TypedArray
            ab = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer
        } else {
            ab = data as ArrayBuffer
        }
        this.chunks.push(ab)
        return this
    }

    digest(): Buffer
    digest(encoding: 'hex' | 'base64'): string
    digest(encoding?: 'hex' | 'base64'): Buffer | string {
        // Combine all chunks
        const totalLength = this.chunks.reduce((sum, ab) => sum + ab.byteLength, 0)
        const combined = new Uint8Array(totalLength)
        let offset = 0
        for (const ab of this.chunks) {
            combined.set(new Uint8Array(ab), offset)
            offset += ab.byteLength
        }

        // Call appropriate native hash function
        let hashAb: ArrayBuffer
        switch (this.algorithm) {
            case 'sha1':
                hashAb = native.sha1(combined.buffer as ArrayBuffer)
                break
            case 'sha256':
                hashAb = native.sha256(combined.buffer as ArrayBuffer)
                break
            case 'sha224':
                hashAb = native.sha224(combined.buffer as ArrayBuffer)
                break
            case 'sha384':
                hashAb = native.sha384(combined.buffer as ArrayBuffer)
                break
            case 'sha512':
                hashAb = native.sha512(combined.buffer as ArrayBuffer)
                break
            case 'sha512-224':
                hashAb = native.sha512_224(combined.buffer as ArrayBuffer)
                break
            case 'sha512-256':
                hashAb = native.sha512_256(combined.buffer as ArrayBuffer)
                break
            case 'md5':
                hashAb = native.md5(combined.buffer as ArrayBuffer)
                break
            case 'sha3-224':
                hashAb = native.sha3_224(combined.buffer as ArrayBuffer)
                break
            case 'sha3-256':
                hashAb = native.sha3_256(combined.buffer as ArrayBuffer)
                break
            case 'sha3-384':
                hashAb = native.sha3_384(combined.buffer as ArrayBuffer)
                break
            case 'sha3-512':
                hashAb = native.sha3_512(combined.buffer as ArrayBuffer)
                break
            case 'shake128': {
                // SHAKE128 is cSHAKE128 with empty customization; default output is 32 bytes (256 bits)
                const outputLen = this.outputLength ?? 32
                const emptyCustomization = new ArrayBuffer(0)
                hashAb = native.cshake128(combined.buffer as ArrayBuffer, emptyCustomization, outputLen)
                break
            }
            case 'shake256': {
                // SHAKE256 is cSHAKE256 with empty customization; default output is 64 bytes (512 bits)
                const outputLen = this.outputLength ?? 64
                const emptyCustomization = new ArrayBuffer(0)
                hashAb = native.cshake256(combined.buffer as ArrayBuffer, emptyCustomization, outputLen)
                break
            }
            case 'ripemd128':
                hashAb = native.ripemd128(combined.buffer as ArrayBuffer)
                break
            case 'ripemd160':
                hashAb = native.ripemd160(combined.buffer as ArrayBuffer)
                break
            case 'ripemd320':
                hashAb = native.ripemd320(combined.buffer as ArrayBuffer)
                break
            case 'blake3':
                hashAb = native.blake3(combined.buffer as ArrayBuffer)
                break
            case 'blake2b512':
                hashAb = native.blake2b512(combined.buffer as ArrayBuffer)
                break
            case 'blake2s256':
                hashAb = native.blake2s256(combined.buffer as ArrayBuffer)
                break
            case 'sm3':
                hashAb = native.sm3(combined.buffer as ArrayBuffer)
                break
            case 'md5-sha1':
                hashAb = native.md5_sha1(combined.buffer as ArrayBuffer)
                break
            default:
                throw new Error(`Unsupported hash algorithm: ${this.algorithm}`)
        }

        const hashBuf = Buffer.from(hashAb)
        if (encoding === 'hex') return hashBuf.toString('hex')
        if (encoding === 'base64') return hashBuf.toString('base64')
        return hashBuf
    }

    copy(options?: any): Hash {
        const newHash = new Hash(this.algorithm)
        // detailed copy of internal state
        newHash.chunks = this.chunks.slice()
        return newHash
    }

    // Stream stubs covering common methods and properties
    readable = true
    writable = true
    write(chunk: any, encoding?: any, cb?: any): boolean {
        this.update(chunk)
        if (cb) cb()
        return true
    }
    end(chunk?: any, encoding?: any, cb?: any): this {
        if (chunk) this.update(chunk)
        if (cb) cb()
        return this
    }
    pipe(dest: any, options?: any): any { return dest }
    on(event: string, listener: (...args: any[]) => void): this { return this }
    once(event: string, listener: (...args: any[]) => void): this { return this }
    emit(event: string, ...args: any[]): boolean { return true }
    read(size?: number): any { return null }
    destroy(error?: Error): this { return this }
    pause(): this { return this }
    resume(): this { return this }
    isPaused(): boolean { return false }
    wrap(oldStream: any): this { return this }
    push(chunk: any, encoding?: string): boolean { return false }
    unshift(chunk: any): boolean { return false }
    addListener(event: string, listener: (...args: any[]) => void): this { return this }
    removeListener(event: string, listener: (...args: any[]) => void): this { return this }
    setMaxListeners(n: number): this { return this }
    getMaxListeners(): number { return 0 }
    listeners(event: string): Function[] { return [] }
    rawListeners(event: string): Function[] { return [] }
    listenerCount(event: string): number { return 0 }
    prependListener(event: string, listener: (...args: any[]) => void): this { return this }
    prependOnceListener(event: string, listener: (...args: any[]) => void): this { return this }
    eventNames(): (string | symbol)[] { return [] }
}
