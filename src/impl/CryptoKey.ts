import { Buffer } from '@craftzdog/react-native-buffer'
import { KeyObject } from './KeyObject'

export type BufferSource = ArrayBuffer | ArrayBufferView

export class CryptoKey {
    type: 'secret' | 'private' | 'public'
    extractable: boolean
    algorithm: any
    usages: string[]
    _keyObject: KeyObject
    _raw?: Buffer

    constructor(keyObject: KeyObject, algorithm: any, extractable: boolean, usages: string[], raw?: Buffer) {
        this.type = keyObject.type
        this.extractable = extractable
        this.algorithm = algorithm
        this.usages = usages
        this._keyObject = keyObject
        this._raw = raw
    }
}
