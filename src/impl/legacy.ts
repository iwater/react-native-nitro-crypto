import { Buffer } from '@craftzdog/react-native-buffer'
import { Hash } from './Hash'
import { Cipheriv, Decipheriv, CipherAlgorithm } from './Cipheriv'

// EVP_BytesToKey implementation to match Node.js legacy behavior
// Basically MD5(pass || salt) repeated.
function EVP_BytesToKey(
    password: Buffer,
    keyLen: number,
    ivLen: number
): { key: Buffer; iv: Buffer } {
    const totalLen = keyLen + ivLen
    let validBytes = 0
    let lastHash = Buffer.alloc(0)
    const allBytes = Buffer.alloc(totalLen)

    // No salt supported in createCipher/createDecipher (Node.js legacy uses null salt implied/no salt arg)
    // Actually createCipher(algo, pass) treats pass as buffer, salt is empty?
    // Node.js docs: "The password is used to derive the cipher key and initialization vector (IV). The value must be either a 'string', a 'Buffer', a 'TypedArray', or a 'DataView'."
    // Legacy EVP_BytesToKey behavior implies salt is optional/not used in basic createCipher.

    while (validBytes < totalLen) {
        const hash = new Hash('md5')
        if (lastHash.length > 0) {
            hash.update(lastHash)
        }
        hash.update(password)
        // No salt

        lastHash = hash.digest()

        const len = Math.min(lastHash.length, totalLen - validBytes)
        lastHash.copy(allBytes, validBytes, 0, len)
        validBytes += len
    }

    const key = allBytes.slice(0, keyLen)
    const iv = allBytes.slice(keyLen, totalLen)
    return { key, iv }
}

// Map algorithm to key/iv length
// This is a partial list for common legacy algorithms
const ALGO_LENS: { [key: string]: { key: number; iv: number } } = {
    'aes-128-cbc': { key: 16, iv: 16 },
    'aes-192-cbc': { key: 24, iv: 16 },
    'aes-256-cbc': { key: 32, iv: 16 },
    'aes-128-ecb': { key: 16, iv: 0 },
    'aes-192-ecb': { key: 24, iv: 0 },
    'aes-256-ecb': { key: 32, iv: 0 },
    'des-cbc': { key: 8, iv: 8 },
    'des-ede3-cbc': { key: 24, iv: 8 }, // 3des
    'bf-cbc': { key: 16, iv: 8 }, // blowfish
    'rc4': { key: 16, iv: 0 }, // var len but default 128 bit usually
}

function getLengths(algorithm: string): { key: number; iv: number } {
    const algo = algorithm.toLowerCase()

    // Default fallback if not in map?
    // Node.js legacy usually expects specific ones.
    if (ALGO_LENS[algo]) return ALGO_LENS[algo]

    // Fallbacks or errors
    if (algo.includes('aes-128')) return { key: 16, iv: 16 }
    if (algo.includes('aes-256')) return { key: 32, iv: 16 }

    return { key: 32, iv: 16 } // Dangerous default?
}

// Legacy API: createCipher (insecure, uses MD5)
export function createCipher(algorithm: string, password: string | Buffer | ArrayBuffer | DataView): Cipheriv & any {
    const lengths = getLengths(algorithm)

    let pwd: Buffer
    if (typeof password === 'string') {
        pwd = Buffer.from(password)
    } else if (ArrayBuffer.isView(password)) {
        pwd = Buffer.from(password.buffer as ArrayBuffer, password.byteOffset, password.byteLength)
    } else {
        pwd = Buffer.from(password as ArrayBuffer)
    }

    const { key, iv } = EVP_BytesToKey(
        pwd,
        lengths.key,
        lengths.iv
    )

    return new Cipheriv(algorithm.toLowerCase() as CipherAlgorithm, key, iv)
}

export function createDecipher(algorithm: string, password: string | Buffer | ArrayBuffer | DataView): Decipheriv & any {
    const lengths = getLengths(algorithm)

    let pwd: Buffer
    if (typeof password === 'string') {
        pwd = Buffer.from(password)
    } else if (ArrayBuffer.isView(password)) {
        pwd = Buffer.from(password.buffer as ArrayBuffer, password.byteOffset, password.byteLength)
    } else {
        pwd = Buffer.from(password as ArrayBuffer)
    }

    const { key, iv } = EVP_BytesToKey(
        pwd,
        lengths.key,
        lengths.iv
    )

    return new Decipheriv(algorithm.toLowerCase() as CipherAlgorithm, key, iv)
}
