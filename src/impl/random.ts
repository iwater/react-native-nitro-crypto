import { Buffer } from '@craftzdog/react-native-buffer'
import { native } from '../native'
import { prepareBuffer, toArrayBuffer } from './utils'

export function randomBytes(size: number): Buffer
export function randomBytes(size: number, callback: (err: Error | null, buf: Buffer) => void): void
export function randomBytes(size: number, callback?: (err: Error | null, buf: Buffer) => void): Buffer | void {
    const ab = native.randomBytes(size)
    const buf = Buffer.from(ab)
    if (callback) {
        setTimeout(() => callback(null, buf), 0)
        return
    }
    return buf
}

export function randomFillSync(buffer: Buffer | ArrayBuffer | Uint8Array): Buffer | ArrayBuffer | Uint8Array {
    const len = buffer.byteLength
    const rand = native.randomBytes(len)
    if (Buffer.isBuffer(buffer)) {
        const buf = Buffer.from(rand)
        buf.copy(buffer)
        return buffer
    } else if (ArrayBuffer.isView(buffer)) {
        (buffer as Uint8Array).set(new Uint8Array(rand))
        return buffer
    } else {
        new Uint8Array(buffer).set(new Uint8Array(rand))
        return buffer
    }
}

export function randomFill(buffer: Buffer | ArrayBuffer | Uint8Array, offsetOrCallback?: number | ((err: Error | null, buf: Buffer | ArrayBuffer | Uint8Array) => void), sizeOrCallback?: number | ((err: Error | null, buf: Buffer | ArrayBuffer | Uint8Array) => void), callback?: (err: Error | null, buf: Buffer | ArrayBuffer | Uint8Array) => void): void {
    let off = 0
    let sz = buffer.byteLength
    let cb: ((err: Error | null, buf: Buffer | ArrayBuffer | Uint8Array) => void) | undefined

    if (typeof offsetOrCallback === 'function') {
        cb = offsetOrCallback
    } else {
        off = offsetOrCallback ?? 0
        if (typeof sizeOrCallback === 'function') {
            cb = sizeOrCallback
        } else {
            sz = sizeOrCallback ?? (buffer.byteLength - off)
            cb = callback
        }
    }

    setTimeout(() => {
        try {
            const subarray = buffer instanceof Buffer ? buffer.subarray(off, off + sz) :
                ArrayBuffer.isView(buffer) ? (buffer as Uint8Array).subarray(off, off + sz) :
                    new Uint8Array(buffer, off, sz)

            randomFillSync(subarray)
            if (cb) cb(null, buffer)
        } catch (err: any) {
            if (cb) cb(err, buffer)
        }
    }, 0)
}

export function randomInt(max: number): number
export function randomInt(min: number, max: number): number
export function randomInt(max: number, callback: (err: Error | null, value: number) => void): void
export function randomInt(min: number, max: number, callback: (err: Error | null, value: number) => void): void
export function randomInt(minOrMax: number, maxOrCallback?: number | ((err: Error | null, value: number) => void), callback?: (err: Error | null, value: number) => void): void | number {
    let min = 0
    let max = minOrMax
    let cb: ((err: Error | null, value: number) => void) | undefined

    if (typeof maxOrCallback === 'function') {
        cb = maxOrCallback
        min = 0
        max = minOrMax
    } else if (typeof maxOrCallback === 'number') {
        min = minOrMax
        max = maxOrCallback
        cb = callback
    }

    const range = max - min
    if (range <= 0) throw new Error('max must be greater than min')

    // Sync implementation:
    const randBuf = native.randomBytes(4) // 32-bit int
    const randVal = new Uint32Array(randBuf)[0]
    const val = min + (randVal % range)

    if (cb) {
        setTimeout(() => cb!(null, val), 0)
        return
    }
    return val
}

export function getRandomValues(array: Buffer | ArrayBuffer | Uint8Array | Uint16Array | Uint32Array | Int8Array | Int16Array | Int32Array | BigInt64Array | BigUint64Array): Buffer | ArrayBuffer | Uint8Array | Uint16Array | Uint32Array | Int8Array | Int16Array | Int32Array | BigInt64Array | BigUint64Array {
    return randomFillSync(array as any) as any
}

export function randomUUID(options?: { disableEntropyCache?: boolean }): string {
    const buf = native.randomBytes(16)
    const bytes = new Uint8Array(buf)

    // Set version to 4 (0100xxxx)
    bytes[6] = (bytes[6] & 0x0f) | 0x40
    // Set variant to 10xxxxxx
    bytes[8] = (bytes[8] & 0x3f) | 0x80

    const hex = Buffer.from(bytes).toString('hex')
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

export function secureHeapUsed(): { total: number; min: number; used: number } {
    return { total: 0, min: 0, used: 0 }
}

export function pbkdf2Sync(password: string | Buffer | ArrayBuffer, salt: string | Buffer | ArrayBuffer, iterations: number, keylen: number, digest: string): Buffer {
    if (digest !== 'sha256') {
        // Native only supports sha256 for now as per specs `pbkdf2Sha256`
        // Wait, spec only has `pbkdf2Sha256`.
        // If user wants other digests, we might fail or polyfill?
        // Node defaults to sha1 if not specified but standard now suggests sha256.
        // For now, only support sha256 via native, throw otherwise?
        // Or implement generic pbkdf2 in JS using Hmac?
        // Let's assume sha256 for now or throw.
        throw new Error(`pbkdf2Sync: only sha256 is supported natively. Requested: ${digest}`)
    }
    const passAb = toArrayBuffer(password)
    const saltAb = toArrayBuffer(salt)
    const res = native.pbkdf2Sha256(passAb, saltAb, iterations, keylen)
    return Buffer.from(res)
}

export function scryptSync(password: string | Buffer | ArrayBuffer, salt: string | Buffer | ArrayBuffer, keylen: number, options?: { N?: number, r?: number, p?: number, maxmem?: number }): Buffer {
    const passBuf = prepareBuffer(password)
    const saltBuf = prepareBuffer(salt)
    const N = options?.N ?? 16384
    const r = options?.r ?? 8
    const p = options?.p ?? 1

    return Buffer.from(native.scrypt(passBuf, saltBuf, N, r, p, keylen))
}

export function scrypt(password: string | Buffer | ArrayBuffer, salt: string | Buffer | ArrayBuffer, keylen: number, options?: any, callback?: (err: Error | null, key: Buffer) => void): void {
    let opts = options
    let cb = callback
    if (typeof options === 'function') {
        cb = options
        opts = {}
    }

    setTimeout(() => {
        try {
            const res = scryptSync(password, salt, keylen, opts)
            if (cb) cb(null, res)
        } catch (err: any) {
            if (cb) cb(err, null as any)
        }
    }, 0)
}

export function argon2Sync(password: string | Buffer | ArrayBuffer, salt: string | Buffer | ArrayBuffer, options?: {
    type?: number // 0=Argon2d, 1=Argon2i, 2=Argon2id (default)
    version?: number // 0=0x10, 1=0x13 (default)
    hashLength?: number // default 32
    timeCost?: number // iterations, default 3
    memoryCost?: number // memory in KiB, default 4096 (4MB) or 65536?
    parallelism?: number // default 1
}): Buffer {
    const passAb = toArrayBuffer(password)
    const saltAb = toArrayBuffer(salt)
    const type = options?.type ?? 2
    const version = options?.version ?? 1
    const hashLength = options?.hashLength ?? 32
    const iterations = options?.timeCost ?? 3
    const memoryCost = options?.memoryCost ?? 65536
    const parallelism = options?.parallelism ?? 4

    const resultAb = native.argon2(passAb, saltAb, iterations, memoryCost, parallelism, hashLength, type, version)
    return Buffer.from(resultAb)
}

export function argon2(password: string | Buffer | ArrayBuffer, salt: string | Buffer | ArrayBuffer, options: any, callback?: (err: Error | null, key: Buffer) => void): void {
    let opts = options
    let cb = callback
    if (typeof options === 'function') {
        cb = options
        opts = {}
    }

    setTimeout(() => {
        try {
            const res = argon2Sync(password, salt, opts)
            if (cb) cb(null, res)
        } catch (err: any) {
            if (cb) cb(err, null as any)
        }
    }, 0)
}

export function generatePrimeSync(size: number, options?: { bigint?: boolean }): Buffer | bigint {
    const ab = native.generatePrimeSync(size)
    const buf = Buffer.from(ab)
    if (options?.bigint) {
        return BigInt('0x' + buf.toString('hex'))
    }
    return buf
}

export function checkPrimeSync(candidate: Buffer | ArrayBuffer | bigint): boolean {
    let ab: ArrayBuffer
    if (typeof candidate === 'bigint') {
        const hex = candidate.toString(16)
        ab = Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex').buffer as ArrayBuffer
    } else {
        ab = toArrayBuffer(candidate)
    }
    return native.checkPrimeSync(ab)
}

export function generatePrime(size: number, options: { bigint?: boolean } | undefined, callback: (err: Error | null, prime: Buffer | bigint) => void): void {
    try {
        const result = generatePrimeSync(size, options)
        setTimeout(() => callback(null, result), 0)
    } catch (err) {
        setTimeout(() => callback(err as Error, Buffer.alloc(0)), 0)
    }
}

export function checkPrime(candidate: Buffer | ArrayBuffer | bigint, options: object | undefined, callback: (err: Error | null, result: boolean) => void): void {
    try {
        const result = checkPrimeSync(candidate)
        setTimeout(() => callback(null, result), 0)
    } catch (err) {
        setTimeout(() => callback(err as Error, false), 0)
    }
}
