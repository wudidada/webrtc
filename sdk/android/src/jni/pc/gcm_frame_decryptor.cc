#include "api/crypto/gcm_frame_decryptor.h"
#include "sdk/android/generated_peerconnection_jni/GCMFrameDecryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"
#include <vector>

namespace webrtc {
namespace jni {

static jlong JNI_GCMFrameDecryptor_GetGCMFrameDecryptor(
  JNIEnv* jni, const base::android::JavaParamRef<jintArray>& key_bytes) {

  jintArray key_bytes_array = key_bytes.obj();
  jsize size = jni->GetArrayLength(key_bytes_array);
  jint *key_bytes_ptr = jni->GetIntArrayElements(key_bytes_array, 0);
  std::vector<uint8_t> key_bytes_vector(key_bytes_ptr, key_bytes_ptr + size);
  
  return jlongFromPointer(new GCMFrameDecryptor(key_bytes_vector));
}

}  // namespace jni
}  // namespace webrtc
