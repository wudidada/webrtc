#include "api/crypto/gcm_frame_encryptor.h"

#include <vector>

#include "rtc_base/logging.h"
#include "sdk/android/generated_peerconnection_jni/GCMFrameEncryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"

namespace webrtc {
namespace jni {

static jlong JNI_GCMFrameEncryptor_GetGCMFrameEncryptor(JNIEnv* jni) {
  return jlongFromPointer(new GCMFrameEncryptor());
}

static void JNI_GCMFrameEncryptor_SetKey(
    JNIEnv* jni,
    const base::android::JavaParamRef<jobject>& thiz,
    const base::android::JavaParamRef<jintArray>& key_bytes) {
  jintArray key_bytes_array = key_bytes.obj();
  jsize size = jni->GetArrayLength(key_bytes_array);
  jint* key_bytes_ptr = jni->GetIntArrayElements(key_bytes_array, 0);
  std::vector<uint8_t> key_bytes_vector(key_bytes_ptr, key_bytes_ptr + size);

  RTC_LOG(LS_VERBOSE) << "XXX JNI_GCMFrameEncryptor_SetKey1";
  GCMFrameEncryptor* encryptor =
      reinterpret_cast<GCMFrameEncryptor*>(thiz.obj());
  RTC_LOG(LS_VERBOSE) << "XXX JNI_GCMFrameEncryptor_SetKey2" << encryptor;
  encryptor->SetKey(key_bytes_vector);
  RTC_LOG(LS_VERBOSE) << "XXX JNI_GCMFrameEncryptor_SetKey3";
}

}  // namespace jni
}  // namespace webrtc
