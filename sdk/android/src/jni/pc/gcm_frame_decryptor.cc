#include "api/crypto/gcm_frame_decryptor.h"

#include <vector>

#include "rtc_base/logging.h"
#include "sdk/android/generated_peerconnection_jni/GCMFrameDecryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"

namespace webrtc {
namespace jni {

static jlong JNI_GCMFrameDecryptor_GetGCMFrameDecryptor(JNIEnv* jni) {
  return jlongFromPointer(new GCMFrameDecryptor());
}

static void JNI_GCMFrameDecryptor_SetKey(
    JNIEnv* jni,
    const base::android::JavaParamRef<jobject>& thiz,
    const base::android::JavaParamRef<jintArray>& key_bytes) {
  jintArray key_bytes_array = key_bytes.obj();
  jsize size = jni->GetArrayLength(key_bytes_array);
  jint* key_bytes_ptr = jni->GetIntArrayElements(key_bytes_array, 0);
  std::vector<uint8_t> key_bytes_vector(key_bytes_ptr, key_bytes_ptr + size);

  GCMFrameDecryptor* decryptor =
      reinterpret_cast<GCMFrameDecryptor*>(thiz.obj());
  decryptor->SetKey(key_bytes_vector);
  RTC_LOG(LS_VERBOSE) << "XXX JNI_GCMFrameDecryptor_SetKey3";
}
}  // namespace jni
}  // namespace webrtc
