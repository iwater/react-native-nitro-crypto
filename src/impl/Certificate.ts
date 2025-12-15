import { Buffer } from '@craftzdog/react-native-buffer'
import { native } from '../native'
import { toArrayBuffer } from './utils'

export class Certificate {
    static exportChallenge(spkac: string | Buffer | ArrayBuffer): Buffer {
        const ab = toArrayBuffer(spkac)
        const resultAb = native.certExportChallenge(ab)
        return Buffer.from(resultAb)
    }

    static exportPublicKey(spkac: string | Buffer | ArrayBuffer): Buffer {
        const ab = toArrayBuffer(spkac)
        const resultAb = native.certExportPublicKey(ab)
        return Buffer.from(resultAb)
    }

    static verifySpkac(spkac: string | Buffer | ArrayBuffer): boolean {
        const ab = toArrayBuffer(spkac)
        return native.certVerifySpkac(ab)
    }
}
