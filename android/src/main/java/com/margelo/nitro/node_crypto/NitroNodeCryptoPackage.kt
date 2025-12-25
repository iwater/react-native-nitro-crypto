package com.margelo.nitro.node_crypto

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager
import android.util.Log

class NitroNodeCryptoPackage : ReactPackage {
  companion object {
    init {
      try {
        System.loadLibrary("RNNodeCrypto")
      } catch (e: Throwable) {
        Log.e("NitroNodeCryptoPackage", "Failed to load RNNodeCrypto library", e)
      }
    }
  }

  override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> {
    return emptyList()
  }

  override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> {
    return emptyList()
  }
}
