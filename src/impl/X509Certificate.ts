import { Buffer } from '@craftzdog/react-native-buffer'
import { native } from '../native'
import { toArrayBuffer } from './utils'
import { KeyObject, createPublicKey } from './KeyObject'
import type { HybridX509Certificate } from '../specs/NitroNodeCrypto.nitro'

export class X509Certificate {
    private nativeX509: HybridX509Certificate

    constructor(buffer: string | Buffer | ArrayBuffer) {
        const ab = toArrayBuffer(buffer)
        this.nativeX509 = native.x509Parse(ab)
    }

    get fingerprint(): string {
        return this.nativeX509.getFingerprint('sha1')
    }

    get fingerprint256(): string {
        return this.nativeX509.getFingerprint('sha256')
    }

    get fingerprint512(): string {
        return this.nativeX509.getFingerprint('sha512')
    }

    get issuer(): string {
        return this.nativeX509.getIssuer()
    }

    /**
     * Returns the issuer certificate if available.
     * Currently returns undefined as we don't have a certificate store or chain validation in place to retrieve it.
     */
    get issuerCertificate(): X509Certificate | undefined {
        // TODO: Implement certificate store / chain resolution / AIA fetching
        return undefined
    }

    get subject(): string {
        return this.nativeX509.getSubject()
    }

    get serialNumber(): string {
        return this.nativeX509.getSerialNumber()
    }

    get validFrom(): string {
        return this.nativeX509.getValidFrom()
    }

    get validTo(): string {
        return this.nativeX509.getValidTo()
    }

    get raw(): Buffer {
        return Buffer.from(this.nativeX509.getRaw())
    }

    toString(): string {
        return this.nativeX509.toPem()
    }

    toJSON(): object {
        return {
            subject: this.subject,
            issuer: this.issuer,
            serialNumber: this.serialNumber,
            validFrom: this.validFrom,
            validTo: this.validTo,
            fingerprint: this.fingerprint,
            fingerprint256: this.fingerprint256,
        }
    }

    // ==================== New Properties ====================

    /**
     * Returns true if this is a CA certificate.
     */
    get ca(): boolean {
        return this.nativeX509.isCa()
    }

    /**
     * Returns the Subject Alternative Name extension as a comma-separated string.
     * Format: "DNS:example.com, DNS:*.example.com, IP Address:192.168.1.1"
     */
    get subjectAltName(): string | undefined {
        const san = this.nativeX509.getSubjectAltName()
        return san || undefined
    }

    /**
     * Returns the public key of this certificate as a KeyObject.
     */
    get publicKey(): KeyObject {
        const derData = this.nativeX509.getPublicKey()
        return createPublicKey({ key: Buffer.from(derData), format: 'der', type: 'spki' })
    }

    /**
     * Returns the key usage extension as an array of usage strings.
     */
    get keyUsage(): string[] {
        const usage = this.nativeX509.getKeyUsage()
        if (!usage) return []
        return usage.split(', ')
    }

    /**
     * Returns the Extended Key Usage extension as an array of OIDs.
     */
    get extKeyUsage(): string[] {
        const eku = this.nativeX509.getExtKeyUsage()
        if (!eku) return []
        return eku.split('\n')
    }

    /**
     * Returns the Authority Info Access extension info.
     * Returns multiline string currently from native.
     * Node.js returns multiline string.
     */
    get infoAccess(): string | undefined {
        const ia = this.nativeX509.getInfoAccess()
        return ia || undefined
    }

    /**
     * Returns a legacy object representation of the certificate.
     */
    toLegacyObject(): any {
        return {
            subject: parseCertString(this.subject),
            issuer: parseCertString(this.issuer),
            subjectaltname: this.subjectAltName,
            infoAccess: parseInfoAccess(this.infoAccess),
            // modulus: this.publicKey.export({ format: 'jwk' }).n, // extract from JWK?
            // exponent: '0x10001',
            valid_from: this.validFrom,
            valid_to: this.validTo,
            fingerprint: this.fingerprint,
            fingerprint256: this.fingerprint256,
            ext_key_usage: this.extKeyUsage,
            serialNumber: this.serialNumber,
            raw: this.raw
        }
    }

    // ==================== Verification Methods ====================

    /**
     * Checks whether the certificate matches the given email address.
     * @param email The email address to check
     * @param options Optional options object with 'subject' property
     * @returns The email if it matches, undefined otherwise
     */
    checkEmail(email: string, options?: { subject?: 'default' | 'always' | 'never' }): string | undefined {
        const checkSubject = options?.subject === 'always' || options?.subject === undefined || options?.subject === 'default'
        const result = this.nativeX509.checkEmail(email, checkSubject)
        return result || undefined
    }

    /**
     * Checks whether the certificate matches the given host name.
     * @param name The host name to check
     * @param options Optional options object
     * @returns The matching name if found, undefined otherwise
     */
    checkHost(name: string, options?: { subject?: 'default' | 'always' | 'never', wildcards?: boolean, partialWildcards?: boolean, multiLabelWildcards?: boolean, singleLabelSubdomains?: boolean }): string | undefined {
        const wildcards = options?.wildcards !== false // default true
        const result = this.nativeX509.checkHost(name, wildcards)
        return result || undefined
    }

    /**
     * Checks whether the certificate matches the given IP address.
     * @param ip The IP address to check (IPv4 or IPv6)
     * @returns The IP if it matches, undefined otherwise
     */
    checkIP(ip: string): string | undefined {
        const result = this.nativeX509.checkIP(ip)
        return result || undefined
    }

    /**
     * Verifies that this certificate was signed by the given public key.
     * @param publicKey The public key to verify against
     * @returns true if verification succeeds, false otherwise
     */
    verify(publicKey: KeyObject): boolean {
        const keyDer = publicKey.export({ format: 'der', type: 'spki' }) as Buffer
        return this.nativeX509.verify(keyDer.buffer.slice(keyDer.byteOffset, keyDer.byteOffset + keyDer.byteLength))
    }

    /**
     * Checks whether this certificate was issued by the given certificate.
     * @param otherCert The potential issuer certificate
     * @returns true if this certificate was issued by otherCert
     */
    checkIssued(otherCert: X509Certificate): boolean {
        return this.nativeX509.checkIssued(otherCert.nativeX509)
    }

    /**
     * Checks whether the private key is consistent with this certificate's public key.
     * @param privateKey The private key to check
     * @returns true if the private key matches
     */
    checkPrivateKey(privateKey: KeyObject): boolean {
        const keyDer = privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer
        return this.nativeX509.checkPrivateKey(keyDer.buffer.slice(keyDer.byteOffset, keyDer.byteOffset + keyDer.byteLength))
    }
}

// ==================== X.509 Helpers ====================

function parseCertString(certString: string): Record<string, string> {
    const res: Record<string, string> = {}
    if (!certString) return res
    const parts = certString.split(/[,+\n]/).map(s => s.trim()).filter(s => s.length > 0)
    for (const part of parts) {
        const eq = part.indexOf('=')
        if (eq !== -1) {
            const key = part.substring(0, eq).trim()
            const val = part.substring(eq + 1).trim()
            res[key] = val
        }
    }
    return res
}

function parseInfoAccess(info?: string): Record<string, string[]> | undefined {
    if (!info) return undefined
    const lines = info.split('\n')
    const res: Record<string, string[]> = {}
    let currentMethod = ''

    for (const line of lines) {
        if (line.startsWith('Method: ')) {
            currentMethod = line.substring(8).trim()
        } else if (line.startsWith('Location: ')) {
            const location = line.substring(10).trim()
            let url = location
            if (url.startsWith('URI:')) url = url.substring(4)

            if (currentMethod) {
                if (!res[currentMethod]) res[currentMethod] = []
                res[currentMethod].push(url)
            }
        }
    }
    return Object.keys(res).length > 0 ? res : undefined
}
