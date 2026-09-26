import { Buffer } from 'react-native-nitro-buffer'
import { native } from '../native'
import type { HybridECDH } from '../specs/NitroNodeCrypto.nitro'
import { toArrayBuffer } from './utils'
import { KeyObject } from './KeyObject'

export class ECDH {
    private nativeECDH: HybridECDH
    /** 构造时传入的曲线名 —— 只用于**报错信息**（让「这条曲线不支持某操作」可指名）。 */
    private curveName: string

    constructor(curveName: string) {
        this.curveName = curveName
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

    sign(data: string | Buffer | ArrayBuffer, encoding?: BufferEncoding): Buffer | string {
        const ab = toArrayBuffer(data)
        const signatureAb = this.nativeECDH.sign(ab)
        // ⚠️ 空签名有**两种**原因，必须分开报 —— 否则「忘了 generateKeys()」会被误读成
        //    「这条曲线不支持签名」。实测：未生成密钥时 `getPrivateKey()` 长度为 0。
        if (!signatureAb || signatureAb.byteLength === 0) {
            if (this.nativeECDH.getPrivateKey().byteLength === 0) {
                throw new Error(
                    `ECDH.sign requires a private key — call generateKeys() or setPrivateKey() first`
                )
            }
            // 有私钥却签不出来 = 这条曲线没有 ECDSA（目前 P-521 如此；X25519 / X448 本来就没有）。
            // 原先是**静默返回空 Buffer** —— 调用方不查长度就会把空签名当签名传下去。
            throw new Error(
                `ECDH.sign is not available for curve '${this.curveName}' (this curve has no ECDSA)`
            )
        }
        const buf = Buffer.from(signatureAb)
        return encoding ? buf.toString(encoding) : buf
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
