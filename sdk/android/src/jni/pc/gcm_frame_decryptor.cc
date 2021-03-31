#include "api/crypto/gcm_frame_decryptor.h"
#include "sdk/android/generated_peerconnection_jni/GCMFrameDecryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"

namespace webrtc {
namespace jni {

static jlong JNI_GCMFrameDecryptor_GetGCMFrameDecryptor(
    JNIEnv* jni) {
  return jlongFromPointer(new GCMFrameDecryptor());
}

}  // namespace jni
}  // namespace webrtc
