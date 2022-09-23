#include "api/crypto/simple_frame_decryptor.h"

#include <vector>

#include "rtc_base/logging.h"
#include "sdk/android/generated_peerconnection_jni/SimpleFrameDecryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"

namespace webrtc {
namespace jni {

static jlong JNI_SimpleFrameDecryptor_GetSimpleFrameDecryptor(JNIEnv* jni) {
  return jlongFromPointer(new SimpleFrameDecryptor());
}

static void JNI_SimpleFrameDecryptor_SetKey(
    JNIEnv* jni,
    const base::android::JavaParamRef<jobject>& thiz,
    const base::android::JavaParamRef<jintArray>& key_bytes) {
  jintArray key_bytes_array = key_bytes.obj();
  jsize size = jni->GetArrayLength(key_bytes_array);
  jint* key_bytes_ptr = jni->GetIntArrayElements(key_bytes_array, 0);
  std::vector<uint8_t> key_bytes_vector(key_bytes_ptr, key_bytes_ptr + size);

  SimpleFrameDecryptor* decryptor =
      reinterpret_cast<SimpleFrameDecryptor*>(thiz.obj());
  decryptor->SetKey(key_bytes_vector);
  RTC_LOG(LS_VERBOSE) << "XXX JNI_SimpleFrameDecryptor_SetKey3";
}
}  // namespace jni
}  // namespace webrtc
