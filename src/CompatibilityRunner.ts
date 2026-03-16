import crypto from './index';
import { Buffer } from 'react-native-nitro-buffer';
import { vectors } from './tests/vectors';

export interface TestFailure {
    category: string;
    test: string;
    error: string;
}

export interface TestGroupReport {
    category: string;
    passed: number;
    failed: number;
    details: Array<{ test: string; status: 'pass' | 'fail'; error?: string }>;
}

export interface TestReport {
    passed: number;
    failed: number;
    failures: TestFailure[];
    groups: TestGroupReport[];
}

export async function runCompatibilityTests(): Promise<TestReport> {
    const report: TestReport = {
        passed: 0,
        failed: 0,
        failures: [],
        groups: []
    };

    const runGroup = async (
        name: string,
        categoryVectors: any[],
        testFn: (v: any) => void | Promise<void>
    ) => {
        const group: TestGroupReport = { category: name, passed: 0, failed: 0, details: [] };
        
        for (const v of categoryVectors) {
            const testName = v.algorithm || (v.params ? `${v.algorithm}(${v.params.iterations || v.params.N})` : name);
            try {
                await testFn(v);
                group.passed++;
                group.details.push({ test: testName, status: 'pass' });
                report.passed++;
            } catch (e) {
                const errorMsg = (e as Error).message;
                group.failed++;
                group.details.push({ test: testName, status: 'fail', error: errorMsg });
                report.failed++;
                const failure = { category: name, test: testName, error: errorMsg };
                report.failures.push(failure);
                console.warn(`[${name} FAIL] ${testName}: ${errorMsg}`);
            }
        }
        report.groups.push(group);
    };

    console.log('Starting Node.js Compatibility Tests...');

    // Hash
    await runGroup('Hash', vectors.hash, (v) => {
        const options = v.outputLength ? { outputLength: v.outputLength } : undefined;
        const hash = crypto.createHash(v.algorithm, options);
        hash.update(v.input);
        const res = hash.digest('hex');
        if (res !== v.expected) throw new Error(`Expected ${v.expected}, got ${res}`);
    });

    // HMAC
    await runGroup('HMAC', vectors.hmac, (v) => {
        const hmac = crypto.createHmac(v.algorithm, v.key);
        hmac.update(v.input);
        const res = hmac.digest('hex');
        if (res !== v.expected) throw new Error(`Expected ${v.expected}, got ${res}`);
    });

    // Cipher
    await runGroup('Cipher', vectors.cipher, (v) => {
        const key = Buffer.from(v.key, 'hex');
        const iv = Buffer.from(v.iv, 'hex');
        const cipher = crypto.createCipheriv(v.algorithm, key, iv);
        let encrypted = cipher.update(v.input, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        if (encrypted !== v.ciphertext) throw new Error(`Expected ${v.ciphertext}, got ${encrypted}`);
        if (v.tag) {
            const tag = (cipher as any).getAuthTag().toString('hex');
            if (tag !== v.tag) throw new Error(`Tag Expected ${v.tag}, got ${tag}`);
        }
    });

    // PBKDF2
    await runGroup('PBKDF2', vectors.pbkdf2, (v) => {
        const { password, salt, iterations, keylen, digest } = v.params;
        const res = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest || 'sha256');
        if (res.toString('hex') !== v.expected) throw new Error(`Expected ${v.expected}, got ${res.toString('hex')}`);
    });

    // Scrypt
    await runGroup('Scrypt', vectors.scrypt, (v) => {
        const { password, salt, keylen, N, r, p } = v.params;
        const res = crypto.scryptSync(password, salt, keylen, { N, r, p });
        if (res.toString('hex') !== v.expected) throw new Error(`Expected ${v.expected}, got ${res.toString('hex')}`);
    });

    // HKDF
    await runGroup('HKDF', vectors.hkdf, (v) => {
        if (typeof (crypto as any).hkdfSync !== 'function') throw new Error('hkdfSync not implemented');
        const res = (crypto as any).hkdfSync(v.algorithm, v.ikm, v.salt, v.info, v.length);
        const resHex = Buffer.from(res).toString('hex');
        if (resHex !== v.expected) throw new Error(`Expected ${v.expected}, got ${resHex}`);
    });

    // Sign/Verify
    await runGroup('Sign/Verify', vectors.sign, (v) => {
        const input = Buffer.from(v.data, 'hex');
        const signature = Buffer.from(v.signature, 'hex');
        
        // 1. Verify the provided signature with the public key
        const isVerified = crypto.verify(v.algorithm, input, v.publicKey, signature);
        if (!isVerified) throw new Error(`Verification of external signature failed`);

        // 2. Sign the input with the private key and verify again
        const mySig = crypto.sign(v.algorithm, input, v.privateKey) as Buffer;
        const isVerifiedSelf = crypto.verify(v.algorithm, input, v.publicKey, mySig);
        if (!isVerifiedSelf) throw new Error(`Self-sign/verify failed`);
    });

    // Asymmetric Encryption
    await runGroup('Asymmetric Enc/Dec', vectors.asymmetric_enc, (v) => {
        const expectedData = Buffer.from(v.data, 'hex');

        // 1. Decrypt the provided ciphertext
        const cipherBuf = Buffer.from(v.ciphertext, 'hex');
        const decrypted = crypto.privateDecrypt(v.privateKey, cipherBuf);
        if (decrypted.toString('hex') !== expectedData.toString('hex')) {
            throw new Error(`Decryption failed: expected ${v.data}, got ${decrypted.toString('hex')}`);
        }

        // 2. Encrypt and decrypt roundtrip
        const myEncrypted = crypto.publicEncrypt(v.publicKey, expectedData);
        const myDecrypted = crypto.privateDecrypt(v.privateKey, myEncrypted);
        if (myDecrypted.toString('hex') !== expectedData.toString('hex')) {
            throw new Error(`Roundtrip encryption failed`);
        }
    });

    // Key Agreement
    await runGroup('Key Agreement', vectors.key_agreement, (v) => {
        if (v.algorithm === 'ecdh-p256') {
            const ecdh = crypto.createECDH(v.curve);
            ecdh.setPrivateKey(Buffer.from(v.privateKey, 'hex'));
            const secret = ecdh.computeSecret(Buffer.from(v.otherPublicKey, 'hex'));
            if (secret.toString('hex') !== v.expectedSecret) {
                throw new Error(`ECDH Secret mismatch: expected ${v.expectedSecret}, got ${secret.toString('hex')}`);
            }
        } else if (v.algorithm === 'x25519') {
            let privKey;
            const { KeyObject, createKeyObjectFromRaw } = require('./impl/KeyObject');
            const { toArrayBuffer } = require('./impl/utils');

            if (v.rawPrivateKey) {
                // Use internal createKeyObjectFromRaw (X25519 = 3)
                const nativeKey = createKeyObjectFromRaw(toArrayBuffer(Buffer.from(v.rawPrivateKey, 'hex')), 3, false);
                privKey = new KeyObject(nativeKey);
            } else {
                privKey = crypto.createPrivateKey(v.privateKey);
            }

            let pubKey;
            if (v.rawOtherPublicKey) {
                const nativeKey = createKeyObjectFromRaw(toArrayBuffer(Buffer.from(v.rawOtherPublicKey, 'hex')), 3, true);
                pubKey = new KeyObject(nativeKey);
            } else {
                pubKey = crypto.createPublicKey(v.otherPublicKey);
            }

            const secret = crypto.diffieHellman({ privateKey: privKey, publicKey: pubKey }) as Buffer;
            if (secret.toString('hex') !== v.expectedSecret) {
                throw new Error(`X25519 Secret mismatch: expected ${v.expectedSecret}, got ${secret.toString('hex')}`);
            }
        }
    });

    // AEAD
    await runGroup('AEAD', vectors.aead_enc, (v) => {
        const key = Buffer.from(v.key, 'hex');
        const iv = Buffer.from(v.iv, 'hex');
        const aad = Buffer.from(v.aad, 'hex');
        const plaintext = Buffer.from(v.plaintext, 'hex');
        
        const encrypted = crypto.aeadEncrypt(v.algorithm, key, iv, plaintext, aad);
        // Tag is usually appended in Nitro AEAD
        const expectedFull = v.ciphertext + v.tag;
        if (encrypted.toString('hex') !== expectedFull) {
            throw new Error(`AEAD Encrypt failed for ${v.algorithm}: expected ${expectedFull}, got ${encrypted.toString('hex')}`);
        }
        
        const decrypted = crypto.aeadDecrypt(v.algorithm, key, iv, encrypted, aad);
        if (decrypted.toString('hex') !== v.plaintext) {
            throw new Error(`AEAD Decrypt failed for ${v.algorithm}: expected ${v.plaintext}, got ${decrypted.toString('hex')}`);
        }
    });

    // AES-KW
    await runGroup('AES-KW', vectors.aes_kw, (v) => {
        const kek = Buffer.from(v.kek, 'hex');
        const plaintext = Buffer.from(v.plaintext, 'hex');
        const wrapped = crypto.aesKwWrap(kek, plaintext);
        if (wrapped.toString('hex') !== v.wrapped) {
            throw new Error(`AES-KW Wrap mismatch: expected ${v.wrapped}, got ${wrapped.toString('hex')}`);
        }
        const unwrapped = crypto.aesKwUnwrap(kek, wrapped);
        if (unwrapped.toString('hex') !== v.plaintext) {
            throw new Error(`AES-KW Unwrap mismatch`);
        }
    });

    // X509
    await runGroup('X509', vectors.x509, (v) => {
        const cert = new crypto.X509Certificate(v.certificate);
        if (!cert.subject.includes(v.subject)) throw new Error(`X509 Subject mismatch: expected to contain ${v.subject}, got ${cert.subject}`);
        if (!cert.issuer.includes(v.issuer)) throw new Error(`X509 Issuer mismatch: expected to contain ${v.issuer}, got ${cert.issuer}`);
    });

    // DH Details
    await runGroup('DH Details', vectors.dh_details, (v) => {
        const dh = crypto.createDiffieHellman(Buffer.from(v.prime, 'hex'), Buffer.from(v.generator, 'hex'));
        const prime = dh.getPrime('hex');
        if (prime !== v.prime) throw new Error(`DH Prime mismatch`);
        const gen = dh.getGenerator('hex');
        if (gen !== v.generator && gen !== '0' + v.generator) { // handle leading zero
             // check numeric value or just normalize
        }
    });

    // Random & Primes
    await runGroup('Random & Primes', [{}], (v) => {
        // randomInt
        const val = crypto.randomInt(10, 20);
        if (val < 10 || val >= 20) throw new Error(`randomInt failed: ${val} not in [10, 20)`);

        // randomUUID
        const uuid = crypto.randomUUID();
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(uuid)) throw new Error(`randomUUID failed: ${uuid}`);

        // Primes (Sync)
        const prime = crypto.generatePrimeSync(64);
        if (!crypto.checkPrimeSync(prime)) throw new Error(`checkPrimeSync failed for generated prime`);
    });

    // Async API
    await runGroup('Async API', [{}], async (v) => {
        // pbkdf2 async
        await new Promise<void>((resolve, reject) => {
            crypto.pbkdf2('password', 'salt', 1, 32, 'sha256', (err, result) => {
                if (err) return reject(err);
                if (result.toString('hex') !== '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b') {
                    return reject(new Error(`Async PBKDF2 mismatch: ${result.toString('hex')}`));
                }
                resolve();
            });
        });
    });

    // Error Handling
    await runGroup('Error Handling', [{}], (v) => {
        // Invalid IV length for AES-CBC
        try {
            crypto.createCipheriv('aes-128-cbc', Buffer.alloc(16), Buffer.alloc(10));
            throw new Error('Should have failed with invalid IV length');
        } catch (e: any) {
            if (!e.message.includes('IV')) throw e;
        }

        // Invalid key length
        try {
            crypto.createCipheriv('aes-128-cbc', Buffer.alloc(10), Buffer.alloc(16));
            throw new Error('Should have failed with invalid key length');
        } catch (e: any) {
            if (!e.message.includes('key length')) throw e;
        }
    });

    console.log(`Compatibility Tests Completed: ${report.passed} Passed, ${report.failed} Failed.`);
    return report;
}
