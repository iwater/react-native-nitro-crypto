import { Buffer } from 'react-native-nitro-buffer'
import { native } from '../native'
import type { HybridECDH } from '../specs/NitroNodeCrypto.nitro'
import { toArrayBuffer } from './utils'
import { KeyObject } from './KeyObject'

export class ECDH {
    private nativeECDH: HybridECDH

    constructor(curveName: string) {
        this.nativeECDH = native.createECDH(curveName)
    }

    generateKeys(encoding?: BufferEncoding, format?: 'compressed' | 'uncompressed'): Buffer | string {
        this.nativeECDH.generateKeys()
        return this.getPublicKey(encoding, format)
    }

    computeSecret(otherPublicKey: string | Buffer | ArrayBuffer, inputEncoding?: BufferEncoding, outputEncoding?: BufferEncoding): Buffer | string {
        const ab = toArrayBuffer(otherPublicKey)
        const secretAb = this.nativeECDH.computeSecret(ab)
        const buf = Buffer.from(secretAb)
        return outputEncoding ? buf.toString(outputEncoding) : buf
    }

    getPrivateKey(encoding?: BufferEncoding): Buffer | string {
        const ab = this.nativeECDH.getPrivateKey()
        const buf = Buffer.from(ab)
        return encoding ? buf.toString(encoding) : buf
    }

    getPublicKey(encoding?: BufferEncoding, format?: 'compressed' | 'uncompressed'): Buffer | string {
        const compressed = format === 'compressed'
        const ab = this.nativeECDH.getPublicKey(compressed)
        const buf = Buffer.from(ab)
        return encoding ? buf.toString(encoding) : buf
    }

    setPrivateKey(privateKey: string | Buffer | ArrayBuffer): void {
        this.nativeECDH.setPrivateKey(toArrayBuffer(privateKey))
    }

    setPublicKey(publicKey: string | Buffer | ArrayBuffer, encoding?: BufferEncoding): void {
        const ab = toArrayBuffer(publicKey)
        if (!this.nativeECDH.setPublicKey(ab)) {
            throw new Error('Invalid public key')
        }
    }

    static convertKey(key: string | Buffer | KeyObject | ArrayBuffer, curve: string, inputEncoding?: BufferEncoding | 'compressed' | 'uncompressed', outputEncoding?: BufferEncoding, format?: 'compressed' | 'uncompressed'): Buffer | string {
        // key can be KeyObject or buffer

        let keyBuf: Buffer
        if (typeof key === 'string') {
            keyBuf = Buffer.from(key, (inputEncoding === 'compressed' || inputEncoding === 'uncompressed') ? undefined : inputEncoding as BufferEncoding)
        } else if (Buffer.isBuffer(key) || key instanceof ArrayBuffer) {
            keyBuf = Buffer.from(key as any)
        } else {
            // KeyObject
            throw new Error('KeyObject not supported in convertKey yet')
        }

        const ecdh = new ECDH(curve)
        try {
            ecdh.setPublicKey(keyBuf)
            return ecdh.getPublicKey(outputEncoding, format as any) as Buffer | string
        } catch (e) {
            throw new Error('Failed to convert key: ' + e)
        }
    }
}
