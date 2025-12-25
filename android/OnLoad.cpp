#include "RNNodeCryptoOnLoad.hpp"
#include <jni.h>

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
  return margelo::nitro::node_crypto::initialize(vm);
}
