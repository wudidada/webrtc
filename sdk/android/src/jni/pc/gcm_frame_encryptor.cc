#include "api/crypto/gcm_frame_encryptor.h"

#include <vector>

#include "sdk/android/generated_peerconnection_jni/GCMFrameEncryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"

namespace webrtc {
namespace jni {

static jlong JNI_GCMFrameEncryptor_GetGCMFrameEncryptor(JNIEnv* jni) {
  return jlongFromPointer(new GCMFrameEncryptor());
}

static void JNI_GCMFrameEncryptor_SetKey(
    JNIEnv* jni,
    jobject thiz,
    const base::android::JavaParamRef<jintArray>& key_bytes) {
  jintArray key_bytes_array = key_bytes.obj();
  jsize size = jni->GetArrayLength(key_bytes_array);
  jint* key_bytes_ptr = jni->GetIntArrayElements(key_bytes_array, 0);
  std::vector<uint8_t> key_bytes_vector(key_bytes_ptr, key_bytes_ptr + size);
}

}  // namespace jni
}  // namespace webrtc
