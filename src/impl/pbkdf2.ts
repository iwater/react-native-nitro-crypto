import { Buffer } from 'react-native-nitro-buffer'
import { native } from '../native'
import { Hmac } from './Hmac'

export function pbkdf2Sync(
    password: string | Buffer | ArrayBuffer,
    salt: string | Buffer | ArrayBuffer,
    iterations: number,
    keylen: number,
    digest: string = 'sha1'
): Buffer {
    // Parameter validation
    if (iterations < 1) throw new TypeError('Iterations must be a positive integer')
    if (keylen < 0) throw new TypeError('Key length must be a positive integer')

    // Prepare buffers
    const pwdBuf = prepareBuffer(password)
    const saltBuf = prepareBuffer(salt)
    const dig = digest.toLowerCase()

    // Optimization: Use native implementation for supported algorithms
    if (dig === 'sha256') {
        const res = native.pbkdf2Sha256(pwdBuf, saltBuf, iterations, keylen)
        return Buffer.from(res)
    }

    // Polyfill using HMAC-based implementation (RFC 2898)
    // DK = T1 || T2 || ... || T(dklen/hlen)
    // Ti = F(P, S, c, i)
    // F(P, S, c, i) = U1 \xor U2 \xor ... \xor Uc
    // U1 = PRF(P, S || INT_32_BE(i))
    // U2 = PRF(P, U1)
    // ...
    // Uc = PRF(P, Uc-1)

    // Hash length map
    const hashLens: { [key: string]: number } = {
        'sha1': 20,
        'sha256': 32,
        'sha384': 48,
        'sha512': 64,
        'md5': 16
    }

    const hLen = hashLens[dig]
    if (!hLen) throw new Error(`Digest method not supported: ${digest}`)

    const numBlocks = Math.ceil(keylen / hLen)
    const dest = Buffer.alloc(keylen)

    const block = Buffer.alloc(4)
    for (let i = 1; i <= numBlocks; i++) {
        // U1
        block.writeUInt32BE(i, 0)

        const hmac = new Hmac(dig, pwdBuf)
        hmac.update(saltBuf)
        hmac.update(block)
        let U = hmac.digest() // this returns Buffer

        let T = U // Copy? buffer is new instance from digest()

        for (let j = 1; j < iterations; j++) {
            const hmacInner = new Hmac(dig, pwdBuf)
            hmacInner.update(U)
            U = hmacInner.digest()

            // T ^= U
            for (let k = 0; k < hLen; k++) {
                T[k] ^= U[k]
            }
        }

        // Copy T to dest
        const start = (i - 1) * hLen
        const end = Math.min(start + hLen, keylen)
        T.copy(dest, start, 0, end - start)
    }

    return dest
}

export function pbkdf2(
    password: string | Buffer | ArrayBuffer,
    salt: string | Buffer | ArrayBuffer,
    iterations: number,
    keylen: number,
    digest: string,
    callback: (err: Error | null, derivedKey: Buffer) => void
): void {
    setTimeout(() => {
        try {
            const res = pbkdf2Sync(password, salt, iterations, keylen, digest)
            callback(null, res)
        } catch (e) {
            callback(e as Error, null as any)
        }
    }, 0)
}

function prepareBuffer(data: string | Buffer | ArrayBuffer): ArrayBuffer {
    if (typeof data === 'string') {
        const buf = Buffer.from(data, 'utf8')
        return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
    }
    if (Buffer.isBuffer(data)) {
        return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)
    }
    return data
}
