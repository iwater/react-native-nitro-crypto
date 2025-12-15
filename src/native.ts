import { NitroModules } from 'react-native-nitro-modules'
import type { NitroNodeCrypto } from './specs/NitroNodeCrypto.nitro'

export const native = NitroModules.createHybridObject<NitroNodeCrypto>('NitroNodeCrypto')
