import { type HybridObject } from 'react-native-nitro-modules'

export interface HybridDiffieHellman extends HybridObject<{ ios: 'c++', android: 'c++' }> {
    generateKeys(): ArrayBuffer
    computeSecret(otherPublicKey: ArrayBuffer): ArrayBuffer
    getPrime(): ArrayBuffer
    getGenerator(): ArrayBuffer
    getPublicKey(): ArrayBuffer
    getPrivateKey(): ArrayBuffer
    setPublicKey(key: ArrayBuffer): void
    setPrivateKey(key: ArrayBuffer): void
}

export interface HybridCipher extends HybridObject<{ ios: 'c++', android: 'c++' }> {
    update(data: ArrayBuffer): ArrayBuffer
    final(): ArrayBuffer
    setAutoPadding(auto_padding: boolean): void
    setAAD(aad: ArrayBuffer): void
    getAuthTag(): ArrayBuffer
}

export interface HybridDecipher extends HybridObject<{ ios: 'c++', android: 'c++' }> {
    update(data: ArrayBuffer): ArrayBuffer
    final(): ArrayBuffer
    setAutoPadding(auto_padding: boolean): void
    setAAD(aad: ArrayBuffer): void
    setAuthTag(tag: ArrayBuffer): void
}

export interface HybridSign extends HybridObject<{ ios: 'c++', android: 'c++' }> {
    update(data: ArrayBuffer): void
    sign(privateKeyPem: ArrayBuffer): ArrayBuffer
}

export interface HybridVerify extends HybridObject<{ ios: 'c++', android: 'c++' }> {
    update(data: ArrayBuffer): void
    verify(publicKeyPem: ArrayBuffer, signature: ArrayBuffer): boolean
}

// Named types for nitrogen codegen compatibility
export interface KeyPair {
    publicKey: HybridKeyObject
    privateKey: HybridKeyObject
}

export interface MLDSAKeyPairResult {
    publicKey: ArrayBuffer
    secretKey: ArrayBuffer
}

export interface MLKEMOneshotResult {
    ciphertext: ArrayBuffer
    sharedSecret: ArrayBuffer
}

export interface MLKEMKeyPairResult {
    encapsulationKey: ArrayBuffer
    decapsulationKey: ArrayBuffer
}

export interface NitroNodeCrypto extends HybridObject<{ ios: 'c++', android: 'c++' }> {
    // ==================== Random ====================

    /**
     * Generates cryptographically strong pseudo-random data.
     * Corresponds to: crypto.randomBytes(size)
     * @param size The number of bytes to generate.
     */
    randomBytes(size: number): ArrayBuffer

    /**
     * Generates a random prime of specified bit length.
     * Corresponds to: crypto.generatePrimeSync(size)
     * @param bits Bit length of the prime
     */
    generatePrimeSync(bits: number): ArrayBuffer

    /**
     * Checks if a number is prime (Miller-Rabin test).
     * Corresponds to: crypto.checkPrimeSync(candidate)
     * @param candidate Big-endian byte representation of the number
     */
    checkPrimeSync(candidate: ArrayBuffer): boolean

    /**
     * Creates a DiffieHellman with generated prime.
     * @param primeBits Bit length of the prime
     * @param generator Generator value
     */
    createDiffieHellmanWithPrimeLength(primeBits: number, generator: number): HybridDiffieHellman

    // ==================== Hash ====================

    /**
     * Computes the SHA-1 hash (20 bytes).
     * Corresponds to: crypto.createHash('sha1').update(data).digest()
     */
    sha1(data: ArrayBuffer): ArrayBuffer

    /**
     * Computes the SHA-256 hash (32 bytes).
     * Corresponds to: crypto.createHash('sha256').update(data).digest()
     */
    sha256(data: ArrayBuffer): ArrayBuffer

    /**
     * Computes the SHA-512 hash (64 bytes).
     * Corresponds to: crypto.createHash('sha512').update(data).digest()
     */
    sha512(data: ArrayBuffer): ArrayBuffer

    /**
     * Computes the MD5 hash (16 bytes).
     * Corresponds to: crypto.createHash('md5').update(data).digest()
     */
    md5(data: ArrayBuffer): ArrayBuffer

    /**
     * Computes the SHA-384 hash (48 bytes).
     * Corresponds to: crypto.createHash('sha384').update(data).digest()
     */
    sha384(data: ArrayBuffer): ArrayBuffer

    /**
     * Computes the SHA3-256 hash (32 bytes).
     * Corresponds to: subtle.digest('SHA3-256', data)
     */
    sha3_256(data: ArrayBuffer): ArrayBuffer

    /**
     * Computes the SHA3-384 hash (48 bytes).
     * Corresponds to: subtle.digest('SHA3-384', data)
     */
    sha3_384(data: ArrayBuffer): ArrayBuffer

    /**
     * Computes the SHA3-512 hash (64 bytes).
     * Corresponds to: subtle.digest('SHA3-512', data)
     */
    sha3_512(data: ArrayBuffer): ArrayBuffer

    /**
     * Computes cSHAKE128 with variable output length.
     * Corresponds to: subtle.digest({ name: 'cSHAKE128', ... }, data)
     */
    cshake128(data: ArrayBuffer, customization: ArrayBuffer, outputLen: number): ArrayBuffer

    /**
     * Computes cSHAKE256 with variable output length.
     * Corresponds to: subtle.digest({ name: 'cSHAKE256', ... }, data)
     */
    cshake256(data: ArrayBuffer, customization: ArrayBuffer, outputLen: number): ArrayBuffer

    // ==================== HMAC ====================

    /**
     * Creates an HMAC instance.
     * Corresponds to: crypto.createHmac(algorithm, key)
     */
    createHmac(algorithm: string, key: ArrayBuffer): HybridHmac

    // ==================== PBKDF2 ====================

    /**
     * Derives key using PBKDF2-HMAC-SHA256.
     * Corresponds to: crypto.pbkdf2Sync(password, salt, iterations, keylen, 'sha256')
     */
    pbkdf2Sha256(password: ArrayBuffer, salt: ArrayBuffer, iterations: number, keylen: number): ArrayBuffer

    // ==================== Diffie-Hellman ====================

    /**
     * Creates a Diffie-Hellman instance.
     * Corresponds to: crypto.createDiffieHellman(prime, generator)
     */
    createDiffieHellman(prime: ArrayBuffer, generator: ArrayBuffer): HybridDiffieHellman

    // ==================== Cipher / Decipher ====================

    /**
     * Creates a Cipher instance.
     * Corresponds to: crypto.createCipheriv(algorithm, key, iv)
     */
    createCipheriv(algorithm: string, key: ArrayBuffer, iv: ArrayBuffer): HybridCipher

    /**
     * Creates a Decipher instance.
     * Corresponds to: crypto.createDecipheriv(algorithm, key, iv)
     */
    createDecipheriv(algorithm: string, key: ArrayBuffer, iv: ArrayBuffer): HybridDecipher

    // Certificate (SPKAC)
    certExportChallenge(spkac: ArrayBuffer): ArrayBuffer
    certExportPublicKey(spkac: ArrayBuffer): ArrayBuffer
    certVerifySpkac(spkac: ArrayBuffer): boolean

    // Sign / Verify
    createSign(algorithm: string): HybridSign
    createVerify(algorithm: string): HybridVerify

    // X509Certificate
    x509Parse(data: ArrayBuffer): HybridX509Certificate

    // ECDH
    createECDH(curveName: string): HybridECDH

    // KeyObject
    createKeyObjectSecret(data: ArrayBuffer): HybridKeyObject
    createKeyObjectPublic(data: ArrayBuffer): HybridKeyObject
    createKeyObjectPrivate(data: ArrayBuffer): HybridKeyObject
    createKeyObjectFromRaw(data: ArrayBuffer, algorithm: number, is_public: boolean): HybridKeyObject

    // Key Generation
    generateKeyPairRSA(modulusBits: number, publicExponent: number): KeyPair
    generateKeyPairEC(curve: string): KeyPair
    generateKeySecret(length: number): HybridKeyObject
    generateKeyPairEd25519(): KeyPair
    generateKeyPairX25519(): KeyPair
    generateKeyPairX448(): KeyPair

    // Asymmetric Encryption
    publicEncrypt(key: HybridKeyObject, buffer: ArrayBuffer, padding: number): ArrayBuffer
    privateDecrypt(key: HybridKeyObject, buffer: ArrayBuffer, padding: number): ArrayBuffer
    privateEncrypt(key: HybridKeyObject, buffer: ArrayBuffer, padding: number): ArrayBuffer
    publicDecrypt(key: HybridKeyObject, buffer: ArrayBuffer, padding: number): ArrayBuffer

    // Scrypt
    scrypt(password: ArrayBuffer, salt: ArrayBuffer, n: number, r: number, p: number, len: number): ArrayBuffer

    // Ed448 Key Generation
    generateKeyPairEd448(): KeyPair
    generateKeyPairDSA(L: number, N: number): KeyPair
    argon2(password: ArrayBuffer, salt: ArrayBuffer, iterations: number, memoryLimit: number, parallelism: number, hashLength: number, type: number, version: number): ArrayBuffer

    // ==================== ML-DSA (FIPS 204) ====================
    /**
     * Generate ML-DSA key pair.
     * @param level Security level: 44, 65, or 87
     */
    mldsaKeygen(level: number): MLDSAKeyPairResult

    /**
     * Sign data with ML-DSA.
     * @param level Security level: 44, 65, or 87
     * @param secretKey Secret key bytes
     * @param data Data to sign
     */
    mldsaSign(level: number, secretKey: ArrayBuffer, data: ArrayBuffer): ArrayBuffer

    /**
     * Verify ML-DSA signature.
     * @param level Security level: 44, 65, or 87
     * @param publicKey Public key bytes
     * @param data Signed data
     * @param signature Signature
     */
    mldsaVerify(level: number, publicKey: ArrayBuffer, data: ArrayBuffer, signature: ArrayBuffer): boolean

    /**
     * Get ML-DSA signature length for given security level.
     */
    mldsaSigLen(level: number): number

    /**
     * Get ML-DSA public key length for given security level.
     */
    mldsaPkLen(level: number): number

    /**
     * Get ML-DSA secret key length for given security level.
     */
    mldsaSkLen(level: number): number

    // ==================== ML-KEM (FIPS 203) ====================
    /**
     * One-shot ML-KEM: generate keys, encapsulate, and decapsulate.
     * Returns ciphertext and shared secret for testing round-trip.
     * @param level Security level: 512, 768, or 1024
     */
    mlkemOneshot(level: number): MLKEMOneshotResult

    /**
     * Generate ML-KEM key pair.
     * @param level Security level: 512, 768, or 1024
     */
    mlkemKeygen(level: number): MLKEMKeyPairResult

    /**
     * ML-KEM encapsulation.
     * @param level Security level: 512, 768, or 1024
     * @param encapsulationKey Encapsulation (public) key bytes
     */
    mlkemEncapsulate(level: number, encapsulationKey: ArrayBuffer): MLKEMOneshotResult

    /**
     * ML-KEM decapsulation.
     * @param level Security level: 512, 768, or 1024
     * @param decapsulationKey Decapsulation (private) key bytes
     * @param ciphertext Ciphertext from encapsulation
     */
    mlkemDecapsulate(level: number, decapsulationKey: ArrayBuffer, ciphertext: ArrayBuffer): ArrayBuffer

    /**
     * Get ML-KEM encapsulation key length for given security level.
     */
    mlkemEkLen(level: number): number

    /**
     * Get ML-KEM decapsulation key length for given security level.
     */
    mlkemDkLen(level: number): number

    /**
     * Get ML-KEM ciphertext length for given security level.
     */
    mlkemCtLen(level: number): number

    /**
     * Get ML-KEM shared secret length (always 32 bytes).
     */
    mlkemSsLen(level: number): number

    // ==================== AEAD (AES-GCM, ChaCha20-Poly1305) ====================
    /**
     * AEAD encrypt: returns ciphertext with appended auth tag.
     * Algorithms: "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"
     */
    aeadEncrypt(algorithm: string, key: ArrayBuffer, nonce: ArrayBuffer, plaintext: ArrayBuffer, aad: ArrayBuffer): ArrayBuffer

    /**
     * AEAD decrypt: expects ciphertext || tag format.
     */
    aeadDecrypt(algorithm: string, key: ArrayBuffer, nonce: ArrayBuffer, ciphertext: ArrayBuffer, aad: ArrayBuffer): ArrayBuffer

    // ==================== AES-KW (RFC 3394) ====================
    /**
     * Wrap key using AES Key Wrap.
     * @param kek Key Encryption Key
     * @param key Key to wrap
     */
    aesKwWrap(kek: ArrayBuffer, key: ArrayBuffer): ArrayBuffer

    /**
     * Unwrap key using AES Key Wrap.
     * @param kek Key Encryption Key
     * @param wrapped Wrapped key
     */
    aesKwUnwrap(kek: ArrayBuffer, wrapped: ArrayBuffer): ArrayBuffer

    // ==================== DH KeyObject Shared Secret ====================
    /**
     * Compute DH shared secret from KeyObject pointers.
     * Supports X25519, X448, and EC (ECDH) key types.
     * @param privateKey Private HybridKeyObject
     * @param publicKey Public HybridKeyObject
     * @returns Shared secret
     */
    dhComputeSecretFromKeys(privateKey: HybridKeyObject, publicKey: HybridKeyObject): ArrayBuffer

    // ==================== DH KeyObject Factory ====================
    /**
     * Create a DH private key KeyObject.
     * @param prime DH prime (p)
     * @param generator DH generator (g)
     * @param privateValue Private value (x)
     * @returns HybridKeyObject
     */
    createKeyObjectDhPrivate(prime: ArrayBuffer, generator: ArrayBuffer, privateValue: ArrayBuffer): HybridKeyObject

    /**
     * Create a DH public key KeyObject.
     * @param prime DH prime (p)
     * @param generator DH generator (g)
     * @param publicValue Public value (g^x mod p)
     * @returns HybridKeyObject
     */
    createKeyObjectDhPublic(prime: ArrayBuffer, generator: ArrayBuffer, publicValue: ArrayBuffer): HybridKeyObject
}

export interface HybridKeyObject extends HybridObject<{ ios: 'c++', android: 'c++' }> {
    getType(): number // 0=Secret, 1=Public, 2=Private
    getAsymmetricKeyType(): number // 0=RSA, 1=EC, 2=Ed25519, 3=X25519, 4=Ed448, 5=X448, 7=MlKem, 8=MlDsa, 12=Dh, 13-18=PQ variants, 99=Unknown
    extractData(): ArrayBuffer
    exportKey(format: number): ArrayBuffer
    // DH accessors
    getDhPrime(): ArrayBuffer
    getDhGenerator(): ArrayBuffer
    isDhKey(): boolean
    // RSA key details (for asymmetricKeyDetails)
    getRsaModulusBits(): number
    getRsaPublicExponent(): ArrayBuffer
    // EC key details (for asymmetricKeyDetails)
    getEcCurveName(): string
}



export interface HybridX509Certificate extends HybridObject<{ ios: 'c++', android: 'c++' }> {
    getFingerprint(algorithm: string): string
    getIssuer(): string
    getSubject(): string
    getSerialNumber(): string
    getValidFrom(): string
    getValidTo(): string
    getRaw(): ArrayBuffer
    toPem(): string
    // New properties
    isCa(): boolean
    getSubjectAltName(): string
    getPublicKey(): ArrayBuffer
    getKeyUsage(): string
    getExtKeyUsage(): string
    getInfoAccess(): string
    // Verification methods
    checkEmail(email: string, checkSubject: boolean): string
    checkHost(host: string, wildcards: boolean): string
    checkIP(ip: string): string
    verify(publicKey: ArrayBuffer): boolean
    checkIssued(otherCert: HybridX509Certificate): boolean
    checkPrivateKey(privateKey: ArrayBuffer): boolean
}

export interface HybridECDH extends HybridObject<{ ios: 'c++', android: 'c++' }> {
    generateKeys(): ArrayBuffer
    computeSecret(otherPublicKey: ArrayBuffer): ArrayBuffer
    getPrivateKey(): ArrayBuffer
    getPublicKey(compressed: boolean): ArrayBuffer
    setPrivateKey(key: ArrayBuffer): boolean
    setPublicKey(key: ArrayBuffer): boolean
}

export interface HybridHmac extends HybridObject<{ ios: 'c++', android: 'c++' }> {
    update(data: ArrayBuffer): void
    digest(): ArrayBuffer
}
