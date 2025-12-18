import crypto from './index';
import { Buffer } from 'react-native-nitro-buffer';
import { vectors } from './tests/vectors';

export interface TestReport {
    passed: number;
    failed: number;
    failures: Array<{ category: string; test: string; error: string }>;
}

export async function runCompatibilityTests(): Promise<TestReport> {
    const report: TestReport = {
        passed: 0,
        failed: 0,
        failures: []
    };

    console.log('Starting Node.js Compatibility Tests...');

    // Hash
    for (const v of vectors.hash) {
        try {
            // XOF algorithms (shake128/shake256) need outputLength option
            const options = v.outputLength ? { outputLength: v.outputLength } : undefined;
            const hash = crypto.createHash(v.algorithm, options);
            hash.update(v.input);
            const res = hash.digest('hex');
            if (res !== v.expected) {
                console.error(`[Hash FAIL] ${v.algorithm} input="${v.input.substring(0, 20)}..."\n  Exp: ${v.expected}\n  Got: ${res}`);
                throw new Error(`Expected ${v.expected}, got ${res}`);
            }
            report.passed++;
        } catch (e) {
            console.error(`[Hash ERROR] ${v.algorithm}: ${(e as Error).message}\n  Vector: ${JSON.stringify(v)}`);
            report.failed++;
            report.failures.push({ category: 'Hash', test: `${v.algorithm}`, error: (e as Error).message });
        }
    }

    // HMAC
    for (const v of vectors.hmac) {
        try {
            const hmac = crypto.createHmac(v.algorithm, v.key);
            hmac.update(v.input);
            const res = hmac.digest('hex');
            if (res !== v.expected) {
                console.error(`[HMAC FAIL] ${v.algorithm} key="${v.key}" input="${v.input.substring(0, 20)}..."\n  Exp: ${v.expected}\n  Got: ${res}`);
                throw new Error(`Expected ${v.expected}, got ${res}`);
            }
            report.passed++;
        } catch (e) {
            console.error(`[HMAC ERROR] ${v.algorithm}: ${(e as Error).message}`);
            report.failed++;
            report.failures.push({ category: 'HMAC', test: `${v.algorithm}`, error: (e as Error).message });
        }
    }

    // Cipher
    for (const v of vectors.cipher) {
        try {
            const key = Buffer.from(v.key, 'hex');
            const iv = Buffer.from(v.iv, 'hex');
            const cipher = crypto.createCipheriv(v.algorithm, key, iv);
            let encrypted = cipher.update(v.input, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            // Note: Cipher output might be case insensitive hex, but usually lower.
            // Also Node might output `encrypted` different than what we expect? 
            // The vectors generated from Node should match Node output.

            // For GCM/CCM, we need to handle auth tag if we want to match full output, 
            // but the vector `ciphertext` field (if we use the one matching Rust test) implies 
            // we should visually check. 
            // Wait, the generated `v.ciphertext` from our script puts ENCRYPTED only in `ciphertext` field?
            // Let's check generate-compat-vectors.ts. 
            // It puts `encrypted` string into `ciphertext` field.

            if (encrypted !== v.ciphertext) {
                console.error(`[Cipher FAIL] ${v.algorithm}\n  Exp: ${v.ciphertext}\n  Got: ${encrypted}`);
                throw new Error(`Expected ${v.ciphertext}, got ${encrypted}`);
            }

            if (v.tag) {
                const tag = (cipher as any).getAuthTag().toString('hex');
                if (tag !== v.tag) {
                    console.error(`[Cipher Tag FAIL] ${v.algorithm}\n  Exp: ${v.tag}\n  Got: ${tag}`);
                    throw new Error(`Tag Expected ${v.tag}, got ${tag}`);
                }
            }

            report.passed++;
        } catch (e) {
            console.error(`[Cipher ERROR] ${v.algorithm}: ${(e as Error).message}\n  Vector: ${JSON.stringify(v)}`);
            report.failed++;
            report.failures.push({ category: 'Cipher', test: `${v.algorithm}`, error: (e as Error).message });
        }
    }

    // PBKDF2
    for (const v of vectors.kdf) {
        if (v.algorithm !== 'pbkdf2') continue;
        try {
            const { password, salt, iterations, keylen, digest } = v.params;
            const res = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest || 'sha256');
            if (res.toString('hex') !== v.expected) throw new Error(`Expected ${v.expected}, got ${res.toString('hex')}`);
            report.passed++;
        } catch (e) {
            console.error(`[PBKDF2 ERROR] ${v.params.iterations} iterations: ${(e as Error).message}`);
            report.failed++;
            report.failures.push({ category: 'PBKDF2', test: `iter=${v.params.iterations}`, error: (e as Error).message });
        }
    }

    // Scrypt
    for (const v of vectors.kdf) {
        if (v.algorithm !== 'scrypt') continue;
        try {
            const { password, salt, keylen, N, r, p } = v.params;
            const res = crypto.scryptSync(password, salt, keylen, { N, r, p });
            if (res.toString('hex') !== v.expected) throw new Error(`Expected ${v.expected}, got ${res.toString('hex')}`);
            report.passed++;
        } catch (e) {
            console.error(`[Scrypt ERROR] N=${v.params.N}: ${(e as Error).message}`);
            report.failed++;
            report.failures.push({ category: 'Scrypt', test: `N=${v.params.N}`, error: (e as Error).message });
        }
    }

    // HKDF
    for (const v of vectors.hkdf) {
        try {
            // HKDF might be polyfilled in JS or Native
            if (typeof (crypto as any).hkdfSync !== 'function') {
                throw new Error('hkdfSync not implemented');
            }
            const res = (crypto as any).hkdfSync(v.algorithm, v.ikm, v.salt, v.info, v.length);
            const resHex = Buffer.from(res).toString('hex');
            if (resHex !== v.expected) throw new Error(`Expected ${v.expected}, got ${resHex}`);
            report.passed++;
        } catch (e) {
            console.error(`[HKDF ERROR] ${v.algorithm}: ${(e as Error).message}`);
            report.failed++;
            report.failures.push({ category: 'HKDF', test: `${v.algorithm}`, error: (e as Error).message });
        }
    }

    console.log(`Compatibility Tests Completed: ${report.passed} Passed, ${report.failed} Failed.`);
    if (report.failed > 0) {
        console.log('=== FAILURE SUMMARY ===');
        report.failures.forEach((f, i) => {
            console.log(`  [${i + 1}] ${f.category} - ${f.test}: ${f.error}`);
        });
    }
    return report;
}
