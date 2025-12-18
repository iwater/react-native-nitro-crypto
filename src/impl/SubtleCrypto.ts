import { Buffer } from 'react-native-nitro-buffer'
import { native } from '../native'
import { toArrayBuffer, prepareBuffer, base64UrlEncode, base64UrlDecode, getJwkAlg, JsonWebKey } from './utils'
import { KeyObject, createSecretKey, createPublicKey, createPrivateKey, createKeyObjectFromRaw, generateKeyPairSync } from './KeyObject'
import { CryptoKey, BufferSource } from './CryptoKey'
import { Hash } from './Hash'
import { Hmac, HmacAlgorithm, hkdfPolyfill } from './Hmac'
import { Cipheriv, Decipheriv, CipherAlgorithm } from './Cipheriv'
import { Sign, Verify, SignAlgorithm } from './Sign'
import { ECDH } from './ECDH'
import { randomBytes, pbkdf2Sync } from './random'
import { constants } from './constants'

export class SubtleCrypto {
    async digest(algorithm: string | { name: string; length?: number; customization?: BufferSource }, data: BufferSource): Promise<ArrayBuffer> {
        const algoName = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase()

        let buf: ArrayBuffer
        if (ArrayBuffer.isView(data)) {
            // Create a copy to ensure we have a standard ArrayBuffer
            const copy = new Uint8Array(data.byteLength)
            copy.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength))
            buf = copy.buffer as ArrayBuffer
        } else {
            // Handle SharedArrayBuffer if necessary by copying
            if (data instanceof ArrayBuffer) {
                buf = data
            } else {
                // Fallback for SharedArrayBuffer or other types
                const copy = new Uint8Array(data as any)
                const newBuf = new Uint8Array(copy.length)
                newBuf.set(copy)
                buf = newBuf.buffer as ArrayBuffer
            }
        }

        // SHA-1, SHA-256, SHA-384, SHA-512 use native directly
        if (algoName === 'SHA-1') {
            return native.sha1(buf)
        } else if (algoName === 'SHA-256') {
            return native.sha256(buf)
        } else if (algoName === 'SHA-384') {
            return native.sha384(buf)
        } else if (algoName === 'SHA-512') {
            return native.sha512(buf)
        } else if (algoName === 'SHA3-256') {
            return native.sha3_256(buf)
        } else if (algoName === 'SHA3-384') {
            return native.sha3_384(buf)
        } else if (algoName === 'SHA3-512') {
            return native.sha3_512(buf)
        } else if (algoName === 'CSHAKE128') {
            const opts = typeof algorithm === 'object' ? algorithm : {}
            const outputLen = (opts as any).length ?? 32
            let customization: ArrayBuffer = new ArrayBuffer(0)
            if ((opts as any).customization) {
                const c = (opts as any).customization
                if (ArrayBuffer.isView(c)) {
                    customization = c.buffer.slice(c.byteOffset, c.byteOffset + c.byteLength) as ArrayBuffer
                } else {
                    customization = c as ArrayBuffer
                }
            }
            return native.cshake128(buf, customization, outputLen)
        } else if (algoName === 'CSHAKE256') {
            const opts = typeof algorithm === 'object' ? algorithm : {}
            const outputLen = (opts as any).length ?? 64
            let customization: ArrayBuffer = new ArrayBuffer(0)
            if ((opts as any).customization) {
                const c = (opts as any).customization
                if (ArrayBuffer.isView(c)) {
                    customization = c.buffer.slice(c.byteOffset, c.byteOffset + c.byteLength) as ArrayBuffer
                } else {
                    customization = c as ArrayBuffer
                }
            }
            return native.cshake256(buf, customization, outputLen)
        }

        throw new Error(`Unrecognized algorithm name: ${algoName}`)
    }

    async generateKey(algorithm: any, extractable: boolean, keyUsages: string[]): Promise<CryptoKey | { publicKey: CryptoKey, privateKey: CryptoKey }> {
        const algoName = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase()

        if (algoName === 'HMAC') {
            const hashName = algorithm.hash.name?.toUpperCase() || algorithm.hash?.toUpperCase()
            let length = algorithm.length
            if (!length) {
                if (hashName === 'SHA-1') length = 512
                else if (hashName === 'SHA-256') length = 512
                else if (hashName === 'SHA-384') length = 1024
                else if (hashName === 'SHA-512') length = 1024
                else throw new Error('Unknown hash algorithm for HMAC')
            }

            const rawKey = randomBytes(length / 8)
            const keyObj = createSecretKey(rawKey)
            return new CryptoKey(keyObj, { name: 'HMAC', hash: { name: hashName }, length }, extractable, keyUsages, rawKey)
        } else if (algoName === 'RSASSA-PKCS1-V1_5' || algoName === 'RSA-PSS' || algoName === 'RSA-OAEP') {
            const modulusLength = algorithm.modulusLength
            const publicExponent = algorithm.publicExponent
            let pubExpNum = 0x10001
            if (publicExponent) {
                if (publicExponent[0] === 1 && publicExponent[1] === 0 && publicExponent[2] === 1) pubExpNum = 65537
            }

            const hashName = algorithm.hash.name?.toUpperCase() || algorithm.hash?.toUpperCase()

            const pair = generateKeyPairSync('rsa', {
                modulusLength,
                publicExponent: pubExpNum
            })

            const algObj = { ...algorithm, name: algoName, hash: { name: hashName } }

            return {
                publicKey: new CryptoKey(pair.publicKey, algObj, true, keyUsages),
                privateKey: new CryptoKey(pair.privateKey, algObj, extractable, keyUsages)
            }
        } else if (algoName === 'ECDSA' || algoName === 'ECDH') {
            const namedCurve = algorithm.namedCurve
            const pair = generateKeyPairSync('ec', { namedCurve })

            const algObj = { ...algorithm, name: algoName }
            return {
                publicKey: new CryptoKey(pair.publicKey, algObj, true, keyUsages),
                privateKey: new CryptoKey(pair.privateKey, algObj, extractable, keyUsages)
            }
        } else if (algoName === 'ED25519') {
            const pair = generateKeyPairSync('ed25519')
            const algObj = { name: 'Ed25519' }
            return {
                publicKey: new CryptoKey(pair.publicKey, algObj, true, keyUsages),
                privateKey: new CryptoKey(pair.privateKey, algObj, extractable, keyUsages)
            }
        } else if (algoName === 'ED448') {
            const pair = generateKeyPairSync('ed448')
            const algObj = { name: 'Ed448' }
            return {
                publicKey: new CryptoKey(pair.publicKey, algObj, true, keyUsages),
                privateKey: new CryptoKey(pair.privateKey, algObj, extractable, keyUsages)
            }
        } else if (algoName === 'X25519') {
            const pair = generateKeyPairSync('x25519')
            const algObj = { name: 'X25519' }
            return {
                publicKey: new CryptoKey(pair.publicKey, algObj, true, keyUsages),
                privateKey: new CryptoKey(pair.privateKey, algObj, extractable, keyUsages)
            }
        } else if (algoName === 'X448') {
            const pair = generateKeyPairSync('x448')
            const algObj = { name: 'X448' }
            return {
                publicKey: new CryptoKey(pair.publicKey, algObj, true, keyUsages),
                privateKey: new CryptoKey(pair.privateKey, algObj, extractable, keyUsages)
            }
        } else if (algoName === 'AES-CBC' || algoName === 'AES-GCM' || algoName === 'AES-KW' || algoName === 'AES-CTR' || algoName === 'AES-OCB') {
            const length = algorithm.length
            if (!length) throw new Error('AES length required')
            const rawKey = randomBytes(length / 8)
            const keyObj = createSecretKey(rawKey)
            return new CryptoKey(keyObj, { ...algorithm, name: algoName }, extractable, keyUsages, rawKey)
        } else if (algoName === 'ML-DSA-44' || algoName === 'ML-DSA-65' || algoName === 'ML-DSA-87') {
            const levelMap: Record<string, number> = { 'ML-DSA-44': 44, 'ML-DSA-65': 65, 'ML-DSA-87': 87 }
            const level = levelMap[algoName]
            const kp = native.mldsaKeygen(level)
            const algObj = { name: algoName }
            const pubKeyObj = createSecretKey(Buffer.from(kp.publicKey))
            const privKeyObj = createSecretKey(Buffer.from(kp.secretKey))
            return {
                publicKey: new CryptoKey(pubKeyObj, algObj, true, keyUsages, Buffer.from(kp.publicKey)),
                privateKey: new CryptoKey(privKeyObj, algObj, extractable, keyUsages, Buffer.from(kp.secretKey))
            }
        } else if (algoName === 'ML-KEM-512' || algoName === 'ML-KEM-768' || algoName === 'ML-KEM-1024') {
            const levelMap: Record<string, number> = { 'ML-KEM-512': 512, 'ML-KEM-768': 768, 'ML-KEM-1024': 1024 }
            const level = levelMap[algoName]
            const kp = native.mlkemKeygen(level)
            const algObj = { name: algoName }
            const pubKeyObj = createSecretKey(Buffer.from(kp.encapsulationKey))
            const privKeyObj = createSecretKey(Buffer.from(kp.decapsulationKey))
            return {
                publicKey: new CryptoKey(pubKeyObj, algObj, true, ['encapsulate'], Buffer.from(kp.encapsulationKey)),
                privateKey: new CryptoKey(privKeyObj, algObj, extractable, ['decapsulate'], Buffer.from(kp.decapsulationKey))
            }
        } else if (algoName === 'CHACHA20-POLY1305') {
            const length = 256
            const rawKey = randomBytes(length / 8)
            const keyObj = createSecretKey(rawKey)
            const algObj = { name: 'ChaCha20-Poly1305' }
            return new CryptoKey(keyObj, algObj, extractable, keyUsages, rawKey)
        }

        throw new Error(`generateKey not implemented for ${algoName}`)
    }

    async importKey(format: 'raw' | 'raw-public' | 'raw-seed' | 'pkcs8' | 'spki' | 'jwk', keyData: BufferSource | any, algorithm: any, extractable: boolean, keyUsages: string[]): Promise<CryptoKey> {
        const algName = (algorithm.name || algorithm).toUpperCase()

        if (format === 'jwk') {
            const jwk = keyData as JsonWebKey

            if (jwk.kty === 'oct') {
                if (!jwk.k) throw new Error('JWK missing required "k" parameter')
                const keyBuf = base64UrlDecode(jwk.k)
                const keyObj = createSecretKey(keyBuf)
                return new CryptoKey(keyObj, algorithm, extractable, keyUsages, keyBuf)
            }

            if (jwk.kty === 'RSA') {
                if (!jwk.n || !jwk.e) throw new Error('JWK missing required RSA parameters')
                const formatOpts: any = { key: jwk, format: 'jwk' }
                try {
                    const keyObj = jwk.d ? createPrivateKey(formatOpts) : createPublicKey(formatOpts)
                    return new CryptoKey(keyObj, algorithm, extractable, keyUsages)
                } catch (e) {
                    throw new Error('Failed to import RSA JWK: ' + e)
                }
            }

            if (jwk.kty === 'EC' || jwk.kty === 'OKP') {
                if (!jwk.crv || !jwk.x) throw new Error('JWK missing required EC/OKP parameters')

                let algId = -1
                const crv = jwk.crv.toUpperCase()

                if (crv === 'P-256' || crv === 'P-384' || crv === 'P-521') algId = 1
                else if (crv === 'ED25519') algId = 2
                else if (crv === 'X25519') algId = 3
                else if (crv === 'ED448') algId = 4
                else if (crv === 'X448') algId = 5
                else if (crv.startsWith('ML-KEM')) algId = 7
                else if (crv.startsWith('ML-DSA')) algId = 8

                if (algId !== -1) {
                    let data: Buffer
                    let isPublic = true

                    if (jwk.d) {
                        isPublic = false
                        data = base64UrlDecode(jwk.d)
                        if (algId === 1) {
                            const formatOpts: any = { key: jwk, format: 'jwk' }
                            const keyObj = createPrivateKey(formatOpts)
                            return new CryptoKey(keyObj, algorithm, extractable, keyUsages)
                        }
                    } else {
                        if (algId === 1) {
                            if (!jwk.y) throw new Error('JWK missing y for EC')
                            const x = base64UrlDecode(jwk.x)
                            const y = base64UrlDecode(jwk.y)
                            data = Buffer.concat([Buffer.from([0x04]), x, y])
                        } else {
                            data = base64UrlDecode(jwk.x)
                        }
                    }

                    const keyObj = createKeyObjectFromRaw(toArrayBuffer(data), algId, isPublic)
                    if (!keyObj) throw new Error('Failed to create key from raw JWK data')
                    return new CryptoKey(new KeyObject(keyObj), algorithm, extractable, keyUsages, isPublic ? data : undefined)
                }

                const formatOpts: any = { key: jwk, format: 'jwk' }
                const keyObj = jwk.d ? createPrivateKey(formatOpts) : createPublicKey(formatOpts)
                return new CryptoKey(keyObj, algorithm, extractable, keyUsages)
            }

            throw new Error(`Unsupported JWK key type: ${jwk.kty}`)
        }

        const buf = prepareBuffer(keyData as any)
        const keyBuf = Buffer.from(buf)

        if (format === 'raw') {
            if (algName === 'HMAC' || algName.startsWith('AES') || algName === 'CHACHA20-POLY1305' || algName === 'HKDF' || algName === 'PBKDF2') {
                const keyObj = createSecretKey(keyBuf)
                return new CryptoKey(keyObj, algorithm, extractable, keyUsages, keyBuf)
            }

            let algId = -1
            if (algName === 'ECDSA' || algName === 'ECDH') algId = 1
            else if (algName === 'ED25519') algId = 2
            else if (algName === 'X25519') algId = 3
            else if (algName === 'ED448') algId = 4
            else if (algName === 'X448') algId = 5
            else if (algName.startsWith('ML-KEM')) algId = 7
            else if (algName.startsWith('ML-DSA')) algId = 8

            if (algId !== -1) {
                const keyObj = createKeyObjectFromRaw(toArrayBuffer(keyBuf), algId, true)
                if (!keyObj) throw new Error('Failed to import raw key')
                return new CryptoKey(new KeyObject(keyObj), algorithm, extractable, keyUsages, keyBuf)
            }
        }

        // raw-public: explicitly import as public key
        if (format === 'raw-public') {
            let algId = -1
            if (algName === 'ED25519') algId = 2
            else if (algName === 'X25519') algId = 3
            else if (algName === 'ED448') algId = 4
            else if (algName === 'X448') algId = 5
            else if (algName.startsWith('ML-KEM')) algId = 7
            else if (algName.startsWith('ML-DSA')) algId = 8
            else if (algName === 'ECDSA' || algName === 'ECDH') algId = 1

            if (algId !== -1) {
                const keyObj = createKeyObjectFromRaw(toArrayBuffer(keyBuf), algId, true)
                if (!keyObj) throw new Error('Failed to import raw-public key')
                return new CryptoKey(new KeyObject(keyObj), algorithm, extractable, keyUsages, keyBuf)
            }
            throw new Error(`raw-public format not supported for ${algName}`)
        }

        // raw-seed: import private key seed (used for ML-DSA, ML-KEM)
        if (format === 'raw-seed') {
            // For ML-DSA: keyBuf is the secretKey
            // For ML-KEM: keyBuf is the decapsulationKey
            if (algName.startsWith('ML-DSA') || algName.startsWith('ML-KEM')) {
                // Create a CryptoKey with _raw containing the private key bytes
                const keyObj = createSecretKey(keyBuf)
                return new CryptoKey(keyObj, algorithm, extractable, keyUsages, keyBuf)
            }
            throw new Error(`raw-seed format not supported for ${algName}`)
        }

        if (format === 'pkcs8') {
            const keyObj = createPrivateKey({ key: keyBuf, format: 'der', type: 'pkcs8' })
            return new CryptoKey(keyObj, algorithm, extractable, keyUsages)
        }

        if (format === 'spki') {
            const keyObj = createPublicKey({ key: keyBuf, format: 'der', type: 'spki' })
            return new CryptoKey(keyObj, algorithm, extractable, keyUsages)
        }

        throw new Error(`importKey not implemented for format ${format}`)
    }

    async exportKey(format: 'raw' | 'raw-public' | 'raw-seed' | 'pkcs8' | 'spki' | 'jwk', key: CryptoKey): Promise<any> {
        if (!key.extractable) {
            throw new Error('Key is not extractable')
        }

        const algName = (key.algorithm.name || '').toUpperCase()

        if (format === 'raw') {
            if (key._raw) return toArrayBuffer(key._raw)
            try {
                const raw = key._keyObject.export({ type: 'raw' } as any)
                if (raw) return toArrayBuffer(raw as Buffer)
            } catch (e) {
            }
        }

        // raw-public: export public key as raw bytes
        if (format === 'raw-public') {
            if (key.type !== 'public') {
                throw new Error('raw-public format can only export public keys')
            }
            // If we have cached _raw, use it
            if (key._raw) return toArrayBuffer(key._raw)

            // Try to export via hybridKey
            try {
                const raw = key._keyObject.hybridKey.exportKey(4) // 4 = Raw format
                if (raw && raw.byteLength > 0) return raw
            } catch (e) {
                // Fallback: try extractData
                try {
                    const data = key._keyObject.hybridKey.extractData()
                    if (data && data.byteLength > 0) return data
                } catch (e2) {
                }
            }
            throw new Error(`Cannot export ${algName} key as raw-public`)
        }

        // raw-seed: export private key seed (for ML-DSA, ML-KEM)
        if (format === 'raw-seed') {
            if (algName.startsWith('ML-DSA') || algName.startsWith('ML-KEM')) {
                // The _raw field contains the secretKey/decapsulationKey
                if (key._raw) return toArrayBuffer(key._raw)
                throw new Error(`${algName} key missing raw data for raw-seed export`)
            }
            throw new Error(`raw-seed format not supported for ${algName}`)
        }

        if (format === 'pkcs8') {
            if (key.type !== 'private') throw new Error('Key is not private')
            const der = key._keyObject.export({ format: 'der', type: 'pkcs8' })
            return toArrayBuffer(der as Buffer)
        }

        if (format === 'spki') {
            if (key.type !== 'public') throw new Error('Key is not public')
            const der = key._keyObject.export({ format: 'der', type: 'spki' })
            return toArrayBuffer(der as Buffer)
        }

        if (format === 'jwk') {
            const algName = (key.algorithm.name || '').toUpperCase()

            if (key.type === 'secret' && key._raw) {
                const jwk: JsonWebKey = {
                    kty: 'oct',
                    k: base64UrlEncode(key._raw),
                    alg: getJwkAlg(key.algorithm),
                    key_ops: key.usages,
                    ext: key.extractable
                }
                return jwk
            }

            if (key.type === 'public' || key.type === 'private') {
                try {
                    const jwkObj = key._keyObject.export({ format: 'jwk' } as any) as any
                    jwkObj.alg = jwkObj.alg || getJwkAlg(key.algorithm)
                    jwkObj.key_ops = key.usages
                    jwkObj.ext = key.extractable
                    return jwkObj as JsonWebKey
                } catch (e) {
                    const type = key._keyObject.asymmetricKeyType
                    if (type === 'ed25519' || type === 'x25519' || type === 'ed448' || type === 'x448') {
                        const jwk: any = {
                            kty: 'OKP',
                            crv: type === 'ed25519' ? 'Ed25519' : (type === 'x25519' ? 'X25519' : (type === 'ed448' ? 'Ed448' : 'X448')),
                            key_ops: key.usages,
                            ext: key.extractable
                        }
                        if (key.type === 'private') {
                            const priv = key._keyObject.hybridKey.exportKey(4) // Raw
                            if (priv && priv.byteLength > 0) jwk.d = base64UrlEncode(Buffer.from(priv))

                            const spki = key._keyObject.hybridKey.exportKey(0) // Spki
                            if (spki && spki.byteLength > 0) {
                                const spkiBuf = Buffer.from(spki)
                                const rawPub = spkiBuf.slice(-32) // Ed25519/X25519 typically
                                if (type === 'ed448' || type === 'x448') {
                                    // TODO: Better parsing for Ed448/X448
                                } else {
                                    jwk.x = base64UrlEncode(rawPub)
                                }
                            }
                        } else {
                            const raw = key._keyObject.hybridKey.exportKey(4)
                            if (raw && raw.byteLength > 0) jwk.x = base64UrlEncode(Buffer.from(raw))
                        }
                        return jwk
                    } else if (type === 'ml-kem' || type === 'ml-dsa') {
                        const jwk: any = {
                            kty: 'OKP', // Or special kty?
                            crv: algName,
                            key_ops: key.usages,
                            ext: key.extractable
                        }
                        if (key.type === 'private') {
                            const priv = key._keyObject.hybridKey.exportKey(4)
                            if (priv) jwk.d = base64UrlEncode(Buffer.from(priv))
                        } else {
                            const raw = key._keyObject.hybridKey.exportKey(4)
                            if (raw) jwk.x = base64UrlEncode(Buffer.from(raw))
                        }
                        return jwk
                    }
                }
            }
            throw new Error(`Cannot export key type ${key.type} as JWK`)
        }

        throw new Error('exportKey not implemented')
    }

    async sign(algorithm: any, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
        const algoName = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase()

        if (algoName === 'HMAC') {
            if (!key._raw) throw new Error('HMAC key missing raw data')
            const hmac = new Hmac((key.algorithm.hash.name.replace('-', '').toLowerCase() as HmacAlgorithm), key._raw)
            hmac.update(Buffer.from(data as any))
            return toArrayBuffer(hmac.digest())
        }

        if (algoName === 'RSASSA-PKCS1-V1_5' || algoName === 'ECDSA') {
            const hashName = key.algorithm.hash?.name || 'SHA-256'
            const nodeHash = hashName.replace('-', '').toLowerCase() as SignAlgorithm

            // Replicate one-shot sign using Sign class
            const signer = new Sign(nodeHash)
            signer.update(Buffer.from(data as any))
            const signature = signer.sign(key._keyObject) as Buffer
            return toArrayBuffer(signature)
        } else if (algoName === 'RSA-PSS') {
            const hashName = key.algorithm.hash?.name || 'SHA-256'
            if (hashName.replace('-', '').toUpperCase() !== 'SHA256') {
                throw new Error('RSA-PSS currently only supports SHA-256')
            }
            const signer = new Sign('rsa-pss')
            signer.update(Buffer.from(data as any))
            const signature = signer.sign(key._keyObject) as Buffer
            return toArrayBuffer(signature)
        } else if (algoName === 'ED25519') {
            const signer = new Sign('ed25519')
            signer.update(Buffer.from(data as any))
            const signature = signer.sign(key._keyObject) as Buffer
            return toArrayBuffer(signature)
        } else if (algoName === 'ED448') {
            const signer = new Sign('ed448')
            signer.update(Buffer.from(data as any))
            const signature = signer.sign(key._keyObject) as Buffer
            return toArrayBuffer(signature)
        } else if (algoName === 'ML-DSA-44' || algoName === 'ML-DSA-65' || algoName === 'ML-DSA-87') {
            if (!key._raw) throw new Error('ML-DSA key missing raw data')
            const levelMap: Record<string, number> = { 'ML-DSA-44': 44, 'ML-DSA-65': 65, 'ML-DSA-87': 87 }
            const level = levelMap[algoName]
            const sig = native.mldsaSign(level, key._raw.buffer.slice(key._raw.byteOffset, key._raw.byteOffset + key._raw.byteLength), prepareBuffer(data))
            return sig
        }

        throw new Error(`sign not implemented for ${algoName}`)
    }

    async verify(algorithm: any, key: CryptoKey, signature: BufferSource, data: BufferSource): Promise<boolean> {
        const algoName = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase()

        if (algoName === 'RSASSA-PKCS1-V1_5' || algoName === 'ECDSA') {
            const hashName = key.algorithm.hash?.name || 'SHA-256'
            const nodeHash = hashName.replace('-', '').toLowerCase() as SignAlgorithm
            const verifier = new Verify(nodeHash)
            verifier.update(Buffer.from(data as any))
            return verifier.verify(key._keyObject, Buffer.from(signature as any))
        } else if (algoName === 'RSA-PSS') {
            const hashName = key.algorithm.hash?.name || 'SHA-256'
            if (hashName.replace('-', '').toUpperCase() !== 'SHA256') {
                throw new Error('RSA-PSS currently only supports SHA-256')
            }
            const verifier = new Verify('rsa-pss')
            verifier.update(Buffer.from(data as any))
            return verifier.verify(key._keyObject, Buffer.from(signature as any))
        } else if (algoName === 'ED25519') {
            const verifier = new Verify('ed25519')
            verifier.update(Buffer.from(data as any))
            return verifier.verify(key._keyObject, Buffer.from(signature as any))
        } else if (algoName === 'ED448') {
            const verifier = new Verify('ed448')
            verifier.update(Buffer.from(data as any))
            return verifier.verify(key._keyObject, Buffer.from(signature as any))
        } else if (algoName === 'ML-DSA-44' || algoName === 'ML-DSA-65' || algoName === 'ML-DSA-87') {
            if (!key._raw) throw new Error('ML-DSA key missing raw data')
            const levelMap: Record<string, number> = { 'ML-DSA-44': 44, 'ML-DSA-65': 65, 'ML-DSA-87': 87 }
            const level = levelMap[algoName]
            return native.mldsaVerify(level, key._raw.buffer.slice(key._raw.byteOffset, key._raw.byteOffset + key._raw.byteLength), prepareBuffer(data), prepareBuffer(signature))
        }

        throw new Error(`verify not implemented for ${algoName}`)
    }

    async encrypt(algorithm: any, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
        const algoName = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase()

        if (algoName === 'AES-CBC') {
            if (!key._raw) throw new Error('AES key missing raw data')
            const iv = algorithm.iv
            const cipher = new Cipheriv(('aes-' + key.algorithm.length + '-cbc' as CipherAlgorithm), key._raw, Buffer.from(iv as any))
            const encrypted = Buffer.concat([cipher.update(Buffer.from(data as any)) as Buffer, cipher.final() as Buffer])
            return toArrayBuffer(encrypted)
        }

        if (algoName === 'AES-CTR') {
            if (!key._raw) throw new Error('AES key missing raw data')
            const counter = algorithm.counter
            const cipher = new Cipheriv(('aes-' + key.algorithm.length + '-ctr' as CipherAlgorithm), key._raw, Buffer.from(counter as any))
            const encrypted = Buffer.concat([cipher.update(Buffer.from(data as any)) as Buffer, cipher.final() as Buffer])
            return toArrayBuffer(encrypted)
        }

        if (algoName === 'RSA-OAEP') {
            const padding = constants.RSA_PKCS1_OAEP_PADDING
            const res = native.publicEncrypt(key._keyObject.hybridKey, prepareBuffer(data), padding)
            return toArrayBuffer(res)
        }

        if (algoName === 'AES-GCM') {
            if (!key._raw) throw new Error('AES key missing raw data')
            const iv = algorithm.iv
            const aad = algorithm.additionalData || new ArrayBuffer(0)
            const algoStr = 'aes-' + key.algorithm.length + '-gcm'
            const encrypted = native.aeadEncrypt(algoStr,
                key._raw.buffer.slice(key._raw.byteOffset, key._raw.byteOffset + key._raw.byteLength),
                prepareBuffer(iv),
                prepareBuffer(data),
                prepareBuffer(aad))
            return encrypted
        }

        if (algoName === 'CHACHA20-POLY1305') {
            if (!key._raw) throw new Error('ChaCha20 key missing raw data')
            const iv = algorithm.iv
            const aad = algorithm.additionalData || new ArrayBuffer(0)
            const encrypted = native.aeadEncrypt('chacha20-poly1305',
                key._raw.buffer.slice(key._raw.byteOffset, key._raw.byteOffset + key._raw.byteLength),
                prepareBuffer(iv),
                prepareBuffer(data),
                prepareBuffer(aad))
            return encrypted
        }

        if (algoName === 'AES-OCB') {
            if (!key._raw) throw new Error('AES key missing raw data')
            const iv = algorithm.iv
            const aad = algorithm.additionalData || new ArrayBuffer(0)
            const algoStr = 'aes-' + key.algorithm.length + '-ocb'
            const encrypted = native.aeadEncrypt(algoStr,
                key._raw.buffer.slice(key._raw.byteOffset, key._raw.byteOffset + key._raw.byteLength),
                prepareBuffer(iv),
                prepareBuffer(data),
                prepareBuffer(aad))
            return encrypted
        }

        throw new Error('encrypt not implemented')
    }

    async decrypt(algorithm: any, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
        const algoName = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase()

        if (algoName === 'RSA-OAEP') {
            const padding = constants.RSA_PKCS1_OAEP_PADDING
            const res = native.privateDecrypt(key._keyObject.hybridKey, prepareBuffer(data), padding)
            return toArrayBuffer(res)
        }

        if (algoName === 'AES-CBC') {
            if (!key._raw) throw new Error('AES key missing raw data')
            const iv = algorithm.iv
            const decipher = new Decipheriv(('aes-' + key.algorithm.length + '-cbc' as CipherAlgorithm), key._raw, Buffer.from(iv as any))
            const decrypted = Buffer.concat([decipher.update(Buffer.from(data as any)) as Buffer, decipher.final() as Buffer])
            return toArrayBuffer(decrypted)
        }

        if (algoName === 'AES-CTR') {
            if (!key._raw) throw new Error('AES key missing raw data')
            const counter = algorithm.counter
            const decipher = new Decipheriv(('aes-' + key.algorithm.length + '-ctr' as CipherAlgorithm), key._raw, Buffer.from(counter as any))
            const decrypted = Buffer.concat([decipher.update(Buffer.from(data as any)) as Buffer, decipher.final() as Buffer])
            return toArrayBuffer(decrypted)
        }

        if (algoName === 'AES-GCM') {
            if (!key._raw) throw new Error('AES key missing raw data')
            const iv = algorithm.iv
            const aad = algorithm.additionalData || new ArrayBuffer(0)
            const algoStr = 'aes-' + key.algorithm.length + '-gcm'
            const decrypted = native.aeadDecrypt(algoStr,
                key._raw.buffer.slice(key._raw.byteOffset, key._raw.byteOffset + key._raw.byteLength),
                prepareBuffer(iv),
                prepareBuffer(data),
                prepareBuffer(aad))
            return decrypted
        }

        if (algoName === 'CHACHA20-POLY1305') {
            if (!key._raw) throw new Error('ChaCha20 key missing raw data')
            const iv = algorithm.iv
            const aad = algorithm.additionalData || new ArrayBuffer(0)
            const decrypted = native.aeadDecrypt('chacha20-poly1305',
                key._raw.buffer.slice(key._raw.byteOffset, key._raw.byteOffset + key._raw.byteLength),
                prepareBuffer(iv),
                prepareBuffer(data),
                prepareBuffer(aad))
            return decrypted
        }

        if (algoName === 'AES-OCB') {
            if (!key._raw) throw new Error('AES key missing raw data')
            const iv = algorithm.iv
            const aad = algorithm.additionalData || new ArrayBuffer(0)
            const algoStr = 'aes-' + key.algorithm.length + '-ocb'
            const decrypted = native.aeadDecrypt(algoStr,
                key._raw.buffer.slice(key._raw.byteOffset, key._raw.byteOffset + key._raw.byteLength),
                prepareBuffer(iv),
                prepareBuffer(data),
                prepareBuffer(aad))
            return decrypted
        }

        throw new Error('decrypt not implemented')
    }

    async deriveBits(algorithm: any, baseKey: CryptoKey, length: number): Promise<ArrayBuffer> {
        const algoName = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase()

        if (algoName === 'PBKDF2') {
            const salt = Buffer.from(algorithm.salt as any)
            const iterations = algorithm.iterations
            const hashName = (algorithm.hash?.name || algorithm.hash || 'SHA-256').replace('-', '').toLowerCase()
            if (!baseKey._raw) throw new Error('PBKDF2 key missing raw data')
            const derived = pbkdf2Sync(baseKey._raw, salt, iterations, length / 8, hashName)
            return toArrayBuffer(derived)
        }

        if (algoName === 'ECDH') {
            const publicKey = algorithm.public as CryptoKey
            if (!publicKey || publicKey.type !== 'public') throw new Error('ECDH requires public key')
            const curveName = baseKey.algorithm.namedCurve || 'P-256'
            const curveMap: Record<string, string> = {
                'P-256': 'prime256v1',
                'P-384': 'secp384r1',
                'P-521': 'secp521r1',
                'X25519': 'x25519',
                'X448': 'x448'
            }
            const nodeCurve = curveMap[curveName] || curveName
            const ecdh = new ECDH(nodeCurve)

            if (curveName === 'X25519' || curveName === 'X448') {
                const privKeyRaw = Buffer.from(baseKey._keyObject.hybridKey.extractData())
                ecdh.setPrivateKey(privKeyRaw)
                const pubKeyRaw = Buffer.from(publicKey._keyObject.hybridKey.extractData())
                const sharedSecret = ecdh.computeSecret(pubKeyRaw) as Buffer
                const bytes = length / 8
                return toArrayBuffer(sharedSecret.slice(0, bytes))
            }

            const privDer = baseKey._keyObject.export({ format: 'der', type: 'sec1' }) as Buffer
            const privKeyLen = curveName === 'P-256' ? 32 : curveName === 'P-384' ? 48 : 66
            const privKeyRaw = privDer.slice(7, 7 + privKeyLen)
            ecdh.setPrivateKey(privKeyRaw)

            const pubDer = publicKey._keyObject.export({ format: 'der', type: 'spki' }) as Buffer
            const pubKeyLen = curveName === 'P-256' ? 65 : curveName === 'P-384' ? 97 : 133
            const pubKeyRaw = pubDer.slice(-pubKeyLen)

            const sharedSecret = ecdh.computeSecret(pubKeyRaw) as Buffer
            const bytes = length / 8
            return toArrayBuffer(sharedSecret.slice(0, bytes))
        }

        if (algoName === 'HKDF') {
            const hashAlgo = (algorithm.hash?.name || algorithm.hash || 'SHA-256').replace('-', '').toLowerCase()
            const salt = Buffer.from(algorithm.salt as any)
            const info = Buffer.from(algorithm.info as any)
            const raw = baseKey._raw
            if (!raw) throw new Error('HKDF key missing raw data')
            const ikm = raw

            const derived = hkdfPolyfill(hashAlgo, ikm as Buffer, salt, info, length / 8)
            return toArrayBuffer(derived)
        }

        throw new Error(`deriveBits not implemented for ${algoName}`)
    }

    async deriveKey(
        algorithm: any,
        baseKey: CryptoKey,
        derivedKeyAlgorithm: any,
        extractable: boolean,
        keyUsages: string[]
    ): Promise<CryptoKey> {
        const derivedAlgoName = (derivedKeyAlgorithm.name || derivedKeyAlgorithm).toUpperCase()
        let length: number

        if (derivedAlgoName === 'AES-CBC' || derivedAlgoName === 'AES-CTR' || derivedAlgoName === 'AES-GCM' || derivedAlgoName === 'AES-KW') {
            length = derivedKeyAlgorithm.length || 256
        } else if (derivedAlgoName === 'HMAC') {
            length = derivedKeyAlgorithm.length || 256
        } else {
            throw new Error(`deriveKey: unsupported derived algorithm ${derivedAlgoName}`)
        }

        const bits = await this.deriveBits(algorithm, baseKey, length)
        return this.importKey('raw', bits, derivedKeyAlgorithm, extractable, keyUsages)
    }

    async wrapKey(format: 'raw' | 'pkcs8' | 'spki' | 'jwk', key: CryptoKey, wrappingKey: CryptoKey, wrapAlgo: any): Promise<ArrayBuffer> {
        const algoName = (wrapAlgo.name || wrapAlgo).toUpperCase()
        const keyData = await this.exportKey(format, key)

        if (algoName === 'AES-KW') {
            const kekBuf = wrappingKey._raw || Buffer.from(wrappingKey._keyObject.hybridKey.exportKey(4))
            const keyBuf = toArrayBuffer(keyData as Buffer)

            const wrapped = native.aesKwWrap(toArrayBuffer(kekBuf), keyBuf)
            return wrapped
        }

        return this.encrypt(wrapAlgo, wrappingKey, keyData)
    }

    async unwrapKey(
        format: 'raw' | 'pkcs8' | 'spki' | 'jwk',
        wrappedKey: BufferSource,
        unwrappingKey: CryptoKey,
        unwrapAlgo: any,
        unwrappedKeyAlgo: any,
        extractable: boolean,
        keyUsages: string[]
    ): Promise<CryptoKey> {
        const algName = (unwrapAlgo.name || unwrapAlgo).toUpperCase()

        if (algName === 'AES-KW') {
            const kekBuf = unwrappingKey._raw || Buffer.from(unwrappingKey._keyObject.hybridKey.exportKey(4))
            const wrappedBuf = prepareBuffer(wrappedKey)

            const unwrappedAb = native.aesKwUnwrap(toArrayBuffer(kekBuf), wrappedBuf)
            return await this.importKey(format, unwrappedAb, unwrappedKeyAlgo, extractable, keyUsages)
        }

        const decrypted = await this.decrypt(unwrapAlgo, unwrappingKey, wrappedKey)
        return this.importKey(format, decrypted, unwrappedKeyAlgo, extractable, keyUsages)
    }

    async getPublicKey(key: CryptoKey, keyUsages?: string[]): Promise<CryptoKey> {
        if (key.type === 'public') {
            return key
        }
        if (key.type !== 'private') {
            throw new Error('getPublicKey requires a private or public key')
        }
        const publicKeyObj = createPublicKey(key._keyObject)
        return new CryptoKey(publicKeyObj, key.algorithm, key.extractable, keyUsages || ['verify'])
    }

    async encapsulateBits(algorithm: any, encapsulationKey: CryptoKey): Promise<{ ciphertext: ArrayBuffer; sharedSecret: ArrayBuffer }> {
        const algoName = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase()

        if (algoName === 'ML-KEM-512' || algoName === 'ML-KEM-768' || algoName === 'ML-KEM-1024') {
            const levelMap: Record<string, number> = { 'ML-KEM-512': 512, 'ML-KEM-768': 768, 'ML-KEM-1024': 1024 }
            const level = levelMap[algoName]
            if (!encapsulationKey._raw) throw new Error('ML-KEM key missing raw data')
            const ek = encapsulationKey._raw.buffer.slice(
                encapsulationKey._raw.byteOffset,
                encapsulationKey._raw.byteOffset + encapsulationKey._raw.byteLength
            )
            const result = native.mlkemEncapsulate(level, ek)
            return { ciphertext: result.ciphertext, sharedSecret: result.sharedSecret }
        }

        throw new Error(`encapsulateBits not implemented for ${algoName}`)
    }

    async encapsulateKey(
        algorithm: any,
        encapsulationKey: CryptoKey,
        sharedKeyAlgorithm: any,
        extractable: boolean,
        usages: string[]
    ): Promise<{ ciphertext: ArrayBuffer; sharedKey: CryptoKey }> {
        const { ciphertext, sharedSecret } = await this.encapsulateBits(algorithm, encapsulationKey)
        const sharedKey = await this.importKey('raw', sharedSecret, sharedKeyAlgorithm, extractable, usages)
        return { ciphertext, sharedKey }
    }

    async decapsulateBits(algorithm: any, decapsulationKey: CryptoKey, ciphertext: BufferSource): Promise<ArrayBuffer> {
        const algoName = (typeof algorithm === 'string' ? algorithm : algorithm.name).toUpperCase()

        if (algoName === 'ML-KEM-512' || algoName === 'ML-KEM-768' || algoName === 'ML-KEM-1024') {
            const levelMap: Record<string, number> = { 'ML-KEM-512': 512, 'ML-KEM-768': 768, 'ML-KEM-1024': 1024 }
            const level = levelMap[algoName]
            if (!decapsulationKey._raw) throw new Error('ML-KEM key missing raw data')
            const dk = decapsulationKey._raw.buffer.slice(
                decapsulationKey._raw.byteOffset,
                decapsulationKey._raw.byteOffset + decapsulationKey._raw.byteLength
            )
            return native.mlkemDecapsulate(level, dk, prepareBuffer(ciphertext))
        }

        throw new Error(`decapsulateBits not implemented for ${algoName}`)
    }

    async decapsulateKey(
        algorithm: any,
        decapsulationKey: CryptoKey,
        ciphertext: BufferSource,
        sharedKeyAlgorithm: any,
        extractable: boolean,
        usages: string[]
    ): Promise<CryptoKey> {
        const sharedSecret = await this.decapsulateBits(algorithm, decapsulationKey, ciphertext)
        return this.importKey('raw', sharedSecret, sharedKeyAlgorithm, extractable, usages)
    }

    static supports(operation: string, algorithm: any, _lengthOrAdditionalAlgorithm?: any): boolean {
        const algoName = (typeof algorithm === 'string' ? algorithm : algorithm?.name)?.toUpperCase()
        if (!algoName) return false

        const supportedAlgos: Record<string, string[]> = {
            'encrypt': ['AES-CBC', 'AES-CTR', 'AES-GCM', 'AES-OCB', 'CHACHA20-POLY1305', 'RSA-OAEP'],
            'decrypt': ['AES-CBC', 'AES-CTR', 'AES-GCM', 'AES-OCB', 'CHACHA20-POLY1305', 'RSA-OAEP'],
            'sign': ['HMAC', 'RSASSA-PKCS1-V1_5', 'ECDSA', 'RSA-PSS', 'ED25519', 'ED448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'],
            'verify': ['HMAC', 'RSASSA-PKCS1-V1_5', 'ECDSA', 'RSA-PSS', 'ED25519', 'ED448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'],
            'digest': ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'],
            'generateKey': ['HMAC', 'AES-CBC', 'AES-CTR', 'AES-GCM', 'AES-OCB', 'RSA-OAEP', 'RSASSA-PKCS1-V1_5', 'RSA-PSS', 'ECDSA', 'ECDH', 'ED25519', 'ED448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'],
            'deriveKey': ['PBKDF2', 'HKDF', 'ECDH'],
            'deriveBits': ['PBKDF2', 'HKDF', 'ECDH'],
            'wrapKey': ['AES-CBC', 'AES-CTR', 'AES-GCM', 'AES-OCB', 'AES-KW', 'CHACHA20-POLY1305', 'RSA-OAEP'],
            'unwrapKey': ['AES-CBC', 'AES-CTR', 'AES-GCM', 'AES-OCB', 'AES-KW', 'CHACHA20-POLY1305', 'RSA-OAEP'],
            'importKey': ['HMAC', 'AES-CBC', 'AES-CTR', 'AES-GCM', 'AES-OCB', 'RSA-OAEP', 'RSASSA-PKCS1-V1_5', 'ECDSA', 'ECDH', 'ED25519', 'ED448', 'X25519', 'X448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'],
            'exportKey': ['HMAC', 'AES-CBC', 'AES-CTR', 'AES-GCM', 'AES-OCB', 'RSA-OAEP', 'RSASSA-PKCS1-V1_5', 'ECDSA', 'ECDH', 'ED25519', 'ED448', 'X25519', 'X448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'],
            'encapsulate': ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'],
            'decapsulate': ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'],
        }

        const ops = supportedAlgos[operation.toLowerCase()]
        if (!ops) return false
        return ops.includes(algoName)
    }
}
