#include "api/crypto/gcm_frame_encryptor.h"
#include "sdk/android/generated_peerconnection_jni/GCMFrameEncryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"

namespace webrtc {
namespace jni {

static jlong JNI_GCMFrameEncryptor_GetGCMFrameEncryptor(
    JNIEnv* jni) {
  return jlongFromPointer(new GCMFrameEncryptor());
}

}  // namespace jni
}  // namespace webrtc
