import { Buffer } from '@craftzdog/react-native-buffer'
import { native } from '../native'
import type { HybridSign, HybridVerify } from '../specs/NitroNodeCrypto.nitro'
import { toArrayBuffer } from './utils'
import { KeyObject } from './KeyObject'

export type SignAlgorithm = 'rsa-sha256' | 'sha256' | 'rsa-pss-sha256' | 'rsa-pss' | 'ecdsa-sha256' | 'ecdsa' | 'ec' | 'ed25519' | 'ed448'

export class Sign {
    private nativeSign: HybridSign

    constructor(algorithm: SignAlgorithm) {
        this.nativeSign = native.createSign(algorithm)
    }

    update(data: string | Buffer | ArrayBuffer, inputEncoding?: BufferEncoding): this {
        const dataAb = toArrayBuffer(data, inputEncoding)
        this.nativeSign.update(dataAb)
        return this
    }

    sign(privateKey: string | Buffer | ArrayBuffer | KeyObject, outputEncoding?: 'hex' | 'base64'): Buffer | string {
        let key: string | Buffer | ArrayBuffer
        if (privateKey instanceof KeyObject) {
            // Export as PEM for compatibility with current native implementation
            key = privateKey.export({ format: 'pem', type: 'pkcs1' }) as string
        } else {
            key = privateKey
        }
        const keyAb = toArrayBuffer(key)
        const resultAb = this.nativeSign.sign(keyAb)
        const resultBuf = Buffer.from(resultAb)

        if (outputEncoding === 'hex') return resultBuf.toString('hex')
        if (outputEncoding === 'base64') return resultBuf.toString('base64')
        return resultBuf
    }
}

export class Verify {
    private nativeVerify: HybridVerify

    constructor(algorithm: SignAlgorithm) {
        this.nativeVerify = native.createVerify(algorithm)
    }

    update(data: string | Buffer | ArrayBuffer, inputEncoding?: BufferEncoding): this {
        const dataAb = toArrayBuffer(data, inputEncoding)
        this.nativeVerify.update(dataAb)
        return this
    }

    verify(publicKey: string | Buffer | ArrayBuffer | KeyObject, signature: string | Buffer | ArrayBuffer, signatureEncoding?: BufferEncoding): boolean {
        let key: string | Buffer | ArrayBuffer
        if (publicKey instanceof KeyObject) {
            // Export as PEM
            key = publicKey.export({ format: 'pem', type: 'pkcs1' }) as string // or spki?
        } else {
            key = publicKey
        }
        const keyAb = toArrayBuffer(key)
        const sigAb = toArrayBuffer(signature, signatureEncoding)
        return this.nativeVerify.verify(keyAb, sigAb)
    }
}
