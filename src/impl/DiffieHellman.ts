import { Buffer } from 'react-native-nitro-buffer'
import { native } from '../native'
import type { HybridDiffieHellman } from '../specs/NitroNodeCrypto.nitro'

export class DiffieHellman {
    private nativeDH: HybridDiffieHellman

    constructor(nativeDH: HybridDiffieHellman);
    constructor(prime: string | Buffer | ArrayBuffer, generator: string | Buffer | ArrayBuffer | number);
    constructor(primeLength: number, generator: string | Buffer | ArrayBuffer | number);
    constructor(
        first: string | Buffer | ArrayBuffer | number | HybridDiffieHellman,
        second?: string | Buffer | ArrayBuffer | number
    ) {
        // Check if first arg is a native DH object (duck typing)
        if (first && typeof first === 'object' && 'generateKeys' in first) {
            this.nativeDH = first as HybridDiffieHellman
            return
        }

        if (typeof first === 'number') {
            // node: createDiffieHellman(prime_length, generator)
            const primeLength = first
            const gen = second ?? 2
            // Node defaults to 2 if not provided for prime length based creation? 
            // Actually Node docs say: `crypto.createDiffieHellman(primeLength[, generator])`
            // generator can be number, string, Buffer. Default 2.

            // Note: native 'createDiffieHellmanWithPrimeLength' takes number for generator.
            // If generator is string/buffer we might not support it in native yet?
            let genNum = 2
            if (typeof gen === 'number') {
                genNum = gen
            } else if (typeof gen === 'string') {
                const buf = Buffer.from(gen)
                if (buf.length === 1) genNum = buf[0]
                else {
                    // Native expects number for generator when generating prime?
                    // Spec says: `createDiffieHellmanWithPrimeLength(primeBits: number, generator: number): HybridDiffieHellman`
                    // So we are limited to number generator for now.
                    // Fallback or throw?
                    // Assuming standard generators 2 or 5.
                    if (buf.length > 0) genNum = buf[0] // risky approximation
                }
            } else if (Buffer.isBuffer(gen)) {
                if (gen.length > 0) genNum = gen[0]
            }

            this.nativeDH = native.createDiffieHellmanWithPrimeLength(primeLength, genNum)
            return
        }

        const prime = first as string | Buffer | ArrayBuffer
        let primeAb: ArrayBuffer
        if (typeof prime === 'string') {
            const buf2 = Buffer.from(prime)
            primeAb = buf2.buffer.slice(buf2.byteOffset, buf2.byteOffset + buf2.byteLength)
        } else if (Buffer.isBuffer(prime)) {
            primeAb = prime.buffer.slice(prime.byteOffset, prime.byteOffset + prime.byteLength)
        } else {
            primeAb = prime
        }

        let generatorAb: ArrayBuffer
        const gen = second ?? 2
        if (typeof gen === 'number') {
            const buf = Buffer.from([gen])
            generatorAb = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
        } else if (typeof gen === 'string') {
            const buf = Buffer.from(gen)
            generatorAb = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
        } else if (Buffer.isBuffer(gen)) {
            generatorAb = gen.buffer.slice(gen.byteOffset, gen.byteOffset + gen.byteLength)
        } else {
            generatorAb = gen
        }

        this.nativeDH = native.createDiffieHellman(primeAb, generatorAb)
    }

    generateKeys(encoding?: 'hex' | 'base64'): Buffer | string {
        const keyAb = this.nativeDH.generateKeys()
        const keyBuf = Buffer.from(keyAb)
        if (encoding === 'hex') return keyBuf.toString('hex')
        if (encoding === 'base64') return keyBuf.toString('base64')
        return keyBuf
    }

    computeSecret(otherPublicKey: string | Buffer | ArrayBuffer, inputEncoding?: 'hex' | 'base64', outputEncoding?: 'hex' | 'base64'): Buffer | string {
        let otherPubAb: ArrayBuffer
        if (typeof otherPublicKey === 'string') {
            const buf = Buffer.from(otherPublicKey, inputEncoding)
            otherPubAb = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
        } else if (Buffer.isBuffer(otherPublicKey)) {
            otherPubAb = otherPublicKey.buffer.slice(otherPublicKey.byteOffset, otherPublicKey.byteOffset + otherPublicKey.byteLength)
        } else {
            otherPubAb = otherPublicKey
        }

        const secretAb = this.nativeDH.computeSecret(otherPubAb)
        const secretBuf = Buffer.from(secretAb)

        if (outputEncoding === 'hex') return secretBuf.toString('hex')
        if (outputEncoding === 'base64') return secretBuf.toString('base64')
        return secretBuf
    }

    getPrime(encoding?: 'hex' | 'base64'): Buffer | string {
        const ab = this.nativeDH.getPrime()
        const buf = Buffer.from(ab)
        if (encoding === 'hex') return buf.toString('hex')
        if (encoding === 'base64') return buf.toString('base64')
        return buf
    }

    getGenerator(encoding?: 'hex' | 'base64'): Buffer | string {
        const ab = this.nativeDH.getGenerator()
        const buf = Buffer.from(ab)
        if (encoding === 'hex') return buf.toString('hex')
        if (encoding === 'base64') return buf.toString('base64')
        return buf
    }

    getPublicKey(encoding?: 'hex' | 'base64'): Buffer | string | undefined {
        const ab = this.nativeDH.getPublicKey()
        if (!ab) return undefined
        const buf = Buffer.from(ab)
        if (encoding === 'hex') return buf.toString('hex')
        if (encoding === 'base64') return buf.toString('base64')
        return buf
    }

    getPrivateKey(encoding?: 'hex' | 'base64'): Buffer | string | undefined {
        const ab = this.nativeDH.getPrivateKey()
        if (!ab) return undefined
        const buf = Buffer.from(ab)
        if (encoding === 'hex') return buf.toString('hex')
        if (encoding === 'base64') return buf.toString('base64')
        return buf
    }

    setPublicKey(key: string | Buffer | ArrayBuffer, encoding?: 'hex' | 'base64'): void {
        let keyAb: ArrayBuffer
        if (typeof key === 'string') {
            const buf = Buffer.from(key, encoding)
            keyAb = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
        } else if (Buffer.isBuffer(key)) {
            keyAb = key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength)
        } else {
            keyAb = key
        }
        this.nativeDH.setPublicKey(keyAb)
    }

    setPrivateKey(key: string | Buffer | ArrayBuffer, encoding?: 'hex' | 'base64'): void {
        let keyAb: ArrayBuffer
        if (typeof key === 'string') {
            const buf = Buffer.from(key, encoding)
            keyAb = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
        } else if (Buffer.isBuffer(key)) {
            keyAb = key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength)
        } else {
            keyAb = key
        }
        this.nativeDH.setPrivateKey(keyAb)
    }

    // Node.js docs: "A bit field containing any warnings and/or errors resulting from a check of the Diffie-Hellman parameter well-formedness."
    // We don't have this implemented in native side yet (openssl DH_check), so return 0 (no error) for now.
    get verifyError(): number {
        return 0
    }
}

// ==================== DH Group Parameters (RFC 2409/3526) ====================
// Generator is always 2 for these standard groups
export const DH_GROUPS: Record<string, { prime: string, generator: number }> = {
    // modp14: 2048 bits (RFC 3526 Section 3) - Recommended
    modp14: {
        prime: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',
        generator: 2
    },
    // modp15: 3072 bits (RFC 3526 Section 4)
    modp15: {
        prime: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF',
        generator: 2
    },
    // modp16: 4096 bits (RFC 3526 Section 5)
    modp16: {
        prime: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF',
        generator: 2
    },
    // modp17: 6144 bits (RFC 3526 Section 6)
    modp17: {
        prime: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF',
        generator: 2
    },
    // Deprecated groups (still supported for compatibility)
    // modp1: 768 bits (RFC 2409 Section 6.1) - DEPRECATED
    modp1: {
        prime: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE653381FFFFFFFFFFFFFFFF',
        generator: 2
    },
    // modp2: 1024 bits (RFC 2409 Section 6.2) - DEPRECATED
    modp2: {
        prime: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA23732FFFFFFFFFFFFFFFF',
        generator: 2
    },
    // modp5: 1536 bits (RFC 3526 Section 2) - DEPRECATED
    modp5: {
        prime: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF',
        generator: 2
    }
}
