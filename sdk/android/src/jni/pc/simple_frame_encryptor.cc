#include "api/crypto/simple_frame_encryptor.h"

#include <vector>

#include "rtc_base/logging.h"
#include "sdk/android/generated_peerconnection_jni/SimpleFrameEncryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"

namespace webrtc {
namespace jni {

static jlong JNI_SimpleFrameEncryptor_GetSimpleFrameEncryptor(JNIEnv* jni) {
  return jlongFromPointer(new SimpleFrameEncryptor());
}

static void JNI_SimpleFrameEncryptor_SetKey(
    JNIEnv* jni,
    const base::android::JavaParamRef<jobject>& thiz,
    const base::android::JavaParamRef<jintArray>& key_bytes) {
  jintArray key_bytes_array = key_bytes.obj();
  jsize size = jni->GetArrayLength(key_bytes_array);
  jint* key_bytes_ptr = jni->GetIntArrayElements(key_bytes_array, 0);
  std::vector<uint8_t> key_bytes_vector(key_bytes_ptr, key_bytes_ptr + size);

  SimpleFrameEncryptor* encryptor =
      reinterpret_cast<SimpleFrameEncryptor*>(thiz.obj());
  encryptor->SetKey(key_bytes_vector);
  RTC_LOG(LS_VERBOSE) << "XXX JNI_SimpleFrameEncryptor_SetKey3";
}

}  // namespace jni
}  // namespace webrtc
