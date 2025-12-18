import { Buffer } from 'react-native-nitro-buffer'
import { native } from '../native'

export type HashAlgorithm = 'sha1' | 'sha256' | 'sha384' | 'sha512' | 'md5' | 'sha3-256' | 'sha3-384' | 'sha3-512' | 'shake128' | 'shake256'

export class Hash {
    private chunks: ArrayBuffer[] = []
    private outputLength: number | undefined

    constructor(private algorithm: HashAlgorithm, options?: { outputLength?: number }) {
        this.outputLength = options?.outputLength
    }

    update(data: string | Buffer | ArrayBuffer, inputEncoding?: BufferEncoding): this {
        let ab: ArrayBuffer
        if (typeof data === 'string') {
            const buf = Buffer.from(data, inputEncoding || 'utf8')
            ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
        } else if (Buffer.isBuffer(data)) {
            ab = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)
        } else {
            ab = data
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
            case 'sha384':
                hashAb = native.sha384(combined.buffer as ArrayBuffer)
                break
            case 'sha512':
                hashAb = native.sha512(combined.buffer as ArrayBuffer)
                break
            case 'md5':
                hashAb = native.md5(combined.buffer as ArrayBuffer)
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
