import { Buffer } from 'react-native-nitro-buffer'
import { native } from '../native'
import type { HybridKeyObject } from '../specs/NitroNodeCrypto.nitro'
import { toArrayBuffer, JsonWebKey } from './utils'
// Lazy load SubtleCrypto to avoid circular dependency
// import { SubtleCrypto } from './SubtleCrypto' 

export type KeyType = 'secret' | 'public' | 'private'
export type KeyObjectType =
    | 'rsa' | 'rsa-pss' | 'ec' | 'ed25519' | 'x25519' | 'ed448' | 'x448' | 'dsa' | 'dh'
    | 'ml-kem' | 'ml-kem-512' | 'ml-kem-768' | 'ml-kem-1024'
    | 'ml-dsa' | 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87'
    | undefined

export class KeyObject {
    public hybridKey: HybridKeyObject

    constructor(hybridKey: HybridKeyObject) {
        this.hybridKey = hybridKey
    }

    get type(): KeyType {
        const t = this.hybridKey.getType()
        if (t === 0) return 'secret'
        if (t === 1) return 'public'
        if (t === 2) return 'private'
        throw new Error(`Unknown KeyObject type: ${t}`)
    }

    get asymmetricKeyType(): any {
        if (this.type === 'secret') return undefined
        const t = this.hybridKey.getAsymmetricKeyType()
        if (t === 0) return 'rsa'
        if (t === 1) return 'ec'
        if (t === 2) return 'ed25519'
        if (t === 3) return 'x25519'
        if (t === 4) return 'ed448'
        if (t === 5) return 'x448'
        if (t === 6) return 'dsa'
        if (t === 7) return 'ml-kem'
        if (t === 8) return 'ml-dsa'
        if (t === 12) return 'dh'
        // Specific ML-KEM variants
        if (t === 13) return 'ml-kem-512'
        if (t === 14) return 'ml-kem-768'
        if (t === 15) return 'ml-kem-1024'
        // Specific ML-DSA variants
        if (t === 16) return 'ml-dsa-44'
        if (t === 17) return 'ml-dsa-65'
        if (t === 18) return 'ml-dsa-87'
        return undefined
    }



    export(options?: { type?: 'pkcs1' | 'spki' | 'pkcs8' | 'sec1', format?: 'pem' | 'der' | 'jwk' }): Buffer | string | JsonWebKey {
        let exportFormat = 0 // Default (Spki/Pkcs8)
        const typeArg = options?.type?.toLowerCase()
        const formatArg = options?.format?.toLowerCase()

        if (formatArg === 'jwk') {
            // Basic JWK export stub/implementation
            // Ideally uses SubtleCrypto exportKey('jwk') but that's async. 
            // Node's export({format: 'jwk'}) is SYNC.
            // We can try to manually construct JWK or use native if available.
            // For now return a minimal JWK with key ops.
            return { kty: this.asymmetricKeyType === 'rsa' ? 'RSA' : 'EC' } as JsonWebKey
        }

        if (typeArg === 'pkcs1') exportFormat = 2
        else if (typeArg === 'sec1') exportFormat = 3
        else if (typeArg === 'spki') exportFormat = 0
        else if (typeArg === 'pkcs8') exportFormat = 1

        // KeyFormat: Spki=0, Pkcs8=1, Pkcs1=2, Sec1=3, Raw=4
        if (typeArg === 'spki') exportFormat = 0
        if (typeArg === 'pkcs8') exportFormat = 1
        if (typeArg === 'raw') exportFormat = 4

        let dataAb = this.hybridKey.exportKey(exportFormat)

        if (!dataAb || dataAb.byteLength === 0) {
            // Fallback if native export fails or returns empty (e.g. not implemented for that format)
            dataAb = this.hybridKey.extractData()
        }

        const data = Buffer.from(dataAb)

        if (options?.format === 'pem') {
            const typeLower = options.type?.toLowerCase()
            let label = 'PUBLIC KEY'
            if (this.type === 'private') {
                label = 'PRIVATE KEY'
                if (typeLower === 'pkcs1') label = 'RSA PRIVATE KEY'
                if (typeLower === 'sec1') label = 'EC PRIVATE KEY'
            } else if (this.type === 'public') {
                if (typeLower === 'pkcs1' && this.asymmetricKeyType === 'rsa') label = 'RSA PUBLIC KEY'
            }

            const pem = `-----BEGIN ${label}-----\n${data.toString('base64').match(/.{1,64}/g)?.join('\n')}\n-----END ${label}-----\n`
            return pem
        }

        return data
    }
    static from(key: KeyObject | any): KeyObject {
        // Support KeyObject input
        if (key instanceof KeyObject) {
            return key
        }
        // Support CryptoKey input (duck-typing to avoid circular dependency)
        if (key && typeof key === 'object' && '_keyObject' in key && key._keyObject instanceof KeyObject) {
            return key._keyObject
        }
        throw new Error('KeyObject.from: key must be a KeyObject or CryptoKey')
    }


    equals(otherKeyObject: KeyObject): boolean {
        if (!(otherKeyObject instanceof KeyObject)) return false
        if (this.type !== otherKeyObject.type) return false
        if (this.asymmetricKeyType !== otherKeyObject.asymmetricKeyType) return false

        const thisData = Buffer.from(this.hybridKey.extractData())
        const otherData = Buffer.from(otherKeyObject.hybridKey.extractData())
        return thisData.equals(otherData)
    }

    get symmetricKeySize(): number | undefined {
        if (this.type === 'secret') {
            return this.hybridKey.extractData().byteLength
        }
        return undefined
    }

    get asymmetricKeyDetails(): object | undefined {
        if (this.type === 'secret') return undefined

        const keyType = this.asymmetricKeyType
        const details: Record<string, any> = {}

        if (keyType === 'rsa' || keyType === 'rsa-pss') {
            // Get RSA modulus length from native
            const modulusLength = this.hybridKey.getRsaModulusBits?.()
            if (modulusLength && modulusLength > 0) {
                details.modulusLength = modulusLength
            }

            // Get RSA public exponent from native (as bigint for Node.js compat)
            const expBuffer = this.hybridKey.getRsaPublicExponent?.()
            if (expBuffer && expBuffer.byteLength > 0) {
                const bytes = new Uint8Array(expBuffer)
                let expValue = 0n
                for (const byte of bytes) {
                    expValue = (expValue << 8n) | BigInt(byte)
                }
                details.publicExponent = expValue
            }
        } else if (keyType === 'ec') {
            // Get EC curve name from native
            const curveName = this.hybridKey.getEcCurveName?.()
            if (curveName) {
                details.namedCurve = curveName
            }
        } else if (keyType === 'dsa') {
            // DSA details not implemented yet
        } else if (keyType === 'dh') {
            // DH details: extractable from dh_prime
        }

        return Object.keys(details).length > 0 ? details : undefined
    }


    /**
     * Converts this KeyObject to a WebCrypto CryptoKey.
     * @param algorithm The algorithm to associate with the key
     * @param extractable Whether the key can be exported
     * @param keyUsages The permitted usages for this key
     * @returns A Promise that resolves to a CryptoKey
     */
    async toCryptoKey(
        algorithm: any,
        extractable: boolean,
        keyUsages: any
    ): Promise<any> {
        // Dynamic import to avoid circular dependency
        const { SubtleCrypto } = await import('./SubtleCrypto')
        const subtle = new SubtleCrypto()

        if (this.type === 'secret') {
            const raw = this.export() as Buffer
            return await subtle.importKey('raw', raw, algorithm, extractable, keyUsages)
        } else if (this.type === 'public') {
            const spki = this.export({ type: 'spki', format: 'der' }) as Buffer
            return await subtle.importKey('spki', spki, algorithm, extractable, keyUsages)
        } else {
            const pkcs8 = this.export({ type: 'pkcs8', format: 'der' }) as Buffer
            return await subtle.importKey('pkcs8', pkcs8, algorithm, extractable, keyUsages)
        }
    }
}

// Factories

/**
 * Creates a KeyObject from a secret key.
 * Compatible with Node.js crypto.createSecretKey API.
 */
export function createSecretKey(key: string | Buffer | ArrayBuffer, encoding?: BufferEncoding): KeyObject {
    let keyAb: ArrayBuffer
    if (typeof key === 'string') {
        if (encoding) {
            const buf = Buffer.from(key, encoding)
            keyAb = toArrayBuffer(buf)
        } else {
            const buf = Buffer.from(key)
            keyAb = toArrayBuffer(buf)
        }
    } else {
        keyAb = toArrayBuffer(key)
    }

    const hybridKey = native.createKeyObjectSecret(keyAb)
    return new KeyObject(hybridKey)
}

/**
 * Creates a public key KeyObject.
 * Compatible with Node.js crypto.createPublicKey API.
 */
export function createPublicKey(key: string | Buffer | ArrayBuffer | KeyObject | { key: string | Buffer | ArrayBuffer, format?: string, type?: string }): KeyObject {
    let rawKey = key
    if (key && typeof key === 'object' && 'key' in key && !Buffer.isBuffer(key) && !(key instanceof ArrayBuffer) && !ArrayBuffer.isView(key) && !(key instanceof KeyObject)) {
        rawKey = (key as any).key
    }

    if (rawKey instanceof KeyObject) {
        if (rawKey.type !== 'public') {
            return new KeyObject((rawKey as any).hybridKey)
        }
        return rawKey
    }

    const keyAb = toArrayBuffer(rawKey instanceof Buffer ? rawKey : Buffer.from(rawKey as any))
    const hybridKey = native.createKeyObjectPublic(keyAb)
    return new KeyObject(hybridKey)
}

/**
 * Creates a private key KeyObject.
 * Compatible with Node.js crypto.createPrivateKey API.
 */
export function createPrivateKey(key: string | Buffer | ArrayBuffer | KeyObject | { key: string | Buffer | ArrayBuffer, format?: string, type?: string }): KeyObject {
    let rawKey = key
    if (key && typeof key === 'object' && 'key' in key && !Buffer.isBuffer(key) && !(key instanceof ArrayBuffer) && !ArrayBuffer.isView(key) && !(key instanceof KeyObject)) {
        rawKey = (key as any).key
    }

    if (rawKey instanceof KeyObject) {
        if (rawKey.type !== 'private') {
            throw new Error('KeyObject is not a private key')
        }
        return rawKey
    }

    const keyAb = toArrayBuffer(rawKey instanceof Buffer ? rawKey : Buffer.from(rawKey as any))
    const hybridKey = native.createKeyObjectPrivate(keyAb)
    return new KeyObject(hybridKey)
}

export function createKeyObjectFromRaw(data: ArrayBuffer, algorithm: number, is_public: boolean): HybridKeyObject {
    return native.createKeyObjectFromRaw(data, algorithm, is_public)
}
export function generateKeyPairSync(
    type: 'rsa' | 'ec' | 'ed25519' | 'ed448' | 'x25519' | 'x448' | 'dsa' | 'rsa-pss' | 'dh'
        | 'ml-kem-512' | 'ml-kem-768' | 'ml-kem-1024'
        | 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87',
    options?: any
): any {


    let publicKey: HybridKeyObject
    let privateKey: HybridKeyObject

    if (type === 'ed25519') {
        const kp = native.generateKeyPairEd25519()
        publicKey = kp.publicKey
        privateKey = kp.privateKey
    } else if (type === 'x25519') {
        const kp = native.generateKeyPairX25519()
        publicKey = kp.publicKey
        privateKey = kp.privateKey
    } else if (type === 'ed448') {
        const kp = native.generateKeyPairEd448()
        publicKey = kp.publicKey
        privateKey = kp.privateKey
    } else if (type === 'x448') {
        const kp = native.generateKeyPairX448()
        publicKey = kp.publicKey
        privateKey = kp.privateKey
    } else if (type === 'dsa') {
        const L = options?.L || 2048
        const N = options?.N || 256
        const kp = native.generateKeyPairDSA(L, N)
        publicKey = kp.publicKey
        privateKey = kp.privateKey
    } else if (type === 'rsa' || type === 'rsa-pss') {
        const modulusLength = options?.modulusLength || 2048
        const publicExponent = options?.publicExponent || 0x10001
        const kp = native.generateKeyPairRSA(modulusLength, publicExponent)
        publicKey = kp.publicKey
        privateKey = kp.privateKey
    } else if (type === 'ec') {
        const curve = options?.namedCurve || 'P-256'
        const kp = native.generateKeyPairEC(curve)
        publicKey = kp.publicKey
        privateKey = kp.privateKey
    } else if (type === 'dh') {
        // Traditional Finite-Field DH
        // Get or generate prime and generator
        let prime: Uint8Array
        let generator: Uint8Array

        if (options?.group) {
            // Use predefined DH group - not implemented yet
            throw new Error(`DH group '${options.group}' not implemented`)
        } else if (options?.prime) {
            // Use provided prime
            prime = new Uint8Array(toArrayBuffer(options.prime))
            generator = new Uint8Array(toArrayBuffer(options.generator || Buffer.from([2])))
        } else {
            // Generate new prime
            const primeLength = options?.primeLength || 2048
            const gen = options?.generator || 2
            // Use existing DiffieHellman class to generate prime
            const { DiffieHellman } = require('./DiffieHellman')
            const dh = new DiffieHellman(primeLength, gen)
            prime = new Uint8Array(toArrayBuffer(dh.getPrime()))
            generator = new Uint8Array(toArrayBuffer(dh.getGenerator()))
        }

        // Generate DH keys using DiffieHellman class
        const { DiffieHellman } = require('./DiffieHellman')
        const dh = new DiffieHellman(Buffer.from(prime), Buffer.from(generator))
        dh.generateKeys()

        const privateValue = toArrayBuffer(dh.getPrivateKey())
        const publicValue = toArrayBuffer(dh.getPublicKey())

        // Create KeyObjects with DH parameters
        publicKey = native.createKeyObjectDhPublic(
            prime.buffer as ArrayBuffer,
            generator.buffer as ArrayBuffer,
            publicValue
        )
        privateKey = native.createKeyObjectDhPrivate(
            prime.buffer as ArrayBuffer,
            generator.buffer as ArrayBuffer,
            privateValue
        )
    } else if (type === 'ml-kem-512' || type === 'ml-kem-768' || type === 'ml-kem-1024') {
        // ML-KEM (Post-Quantum KEM)
        const levelMap: Record<string, number> = { 'ml-kem-512': 512, 'ml-kem-768': 768, 'ml-kem-1024': 1024 }
        const level = levelMap[type]
        const kp = native.mlkemKeygen(level)
        // For ML-KEM, we store raw keys as secret KeyObjects with the algorithm type info
        // Note: native.mlkemKeygen returns { encapsulationKey, decapsulationKey }
        publicKey = native.createKeyObjectSecret(kp.encapsulationKey)
        privateKey = native.createKeyObjectSecret(kp.decapsulationKey)
        // Return as KeyObject (note: type will be 'secret', need proper KeyObject for PQ)
        return {
            publicKey: new KeyObject(publicKey),
            privateKey: new KeyObject(privateKey)
        }
    } else if (type === 'ml-dsa-44' || type === 'ml-dsa-65' || type === 'ml-dsa-87') {
        // ML-DSA (Post-Quantum Signature)
        const levelMap: Record<string, number> = { 'ml-dsa-44': 44, 'ml-dsa-65': 65, 'ml-dsa-87': 87 }
        const level = levelMap[type]
        const kp = native.mldsaKeygen(level)
        // For ML-DSA, we store raw keys as secret KeyObjects
        publicKey = native.createKeyObjectSecret(kp.publicKey)
        privateKey = native.createKeyObjectSecret(kp.secretKey)
        return {
            publicKey: new KeyObject(publicKey),
            privateKey: new KeyObject(privateKey)
        }
    } else {
        throw new Error(`generateKeyPairSync not implemented for ${type}`)
    }



    return {
        publicKey: new KeyObject(publicKey),
        privateKey: new KeyObject(privateKey)
    }
}
