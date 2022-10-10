#include "sdk/android/src/jni/pc/general_frame_encryptor.h"

#include <stdio.h>
#include <jni.h>

#include "sdk/android/generated_peerconnection_jni/GeneralFrameEncryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"
#include "sdk/android/native_api/jni/java_types.h"

#include "rtc_base/logging.h"

namespace webrtc {
namespace jni {
int GeneralFrameEncryptor::Encrypt(cricket::MediaType media_type,
                                   uint32_t ssrc,
                                   rtc::ArrayView<const uint8_t> additional_data,
                                   rtc::ArrayView<const uint8_t> frame,
                                   rtc::ArrayView<uint8_t> encrypted_frame,
                                   size_t* bytes_written) {
  uint8_t unencrypted_bytes = 1;
  switch (media_type) {
    case cricket::MEDIA_TYPE_AUDIO:
      unencrypted_bytes = 1;
      break;
    case cricket::MEDIA_TYPE_VIDEO:
      unencrypted_bytes = 10;
      break;
    case cricket::MEDIA_TYPE_DATA:
      break;
    case cricket::MEDIA_TYPE_UNSUPPORTED:
      break;
  }

  // write unencrypted frame head
  for (size_t i = 0; i < unencrypted_bytes; i++) {
    encrypted_frame[i] = frame[i];
  }

  JNIEnv* env = AttachCurrentThreadIfNeeded();

  // type convert: native to Java
  rtc::ArrayView<const uint8_t> frame_payload = frame.subview(unencrypted_bytes);
  jbyteArray jarrayIn = env->NewByteArray(frame_payload.size());
  env->SetByteArrayRegion(jarrayIn, 0, frame_payload.size(), reinterpret_cast<const jbyte*>(frame_payload.data()));

  // call Java side function
  jclass encryAndDecryClass = GeneralFrameEncryptor_clazz(env);
  CHECK_CLAZZ(env, encryAndDecryClass,
              GeneralFrameEncryptor_clazz(env), NULL);

  jni_generator::JniJavaCallContextChecked call_context;
  call_context.Init<
      base::android::MethodID::TYPE_STATIC>(
      env,
      encryAndDecryClass,
      "encryByte",
      "([B)[B",
      &g_GeneralFrameEncryptor_clazz);

  jbyteArray jarrayOut =
      static_cast<jbyteArray>(env->CallStaticObjectMethod(encryAndDecryClass,
                                                          call_context.base.method_id, jarrayIn));

  int8_t* encrypted_frame_payload = reinterpret_cast<int8_t*>(env->GetByteArrayElements(jarrayOut, 0));
//
//  ScopedJavaLocalRef<jbyteArray> j_encrypted_frame_payload =
//      Java_GeneralFrameEncryptor_encrypt(env, j_frame_payload);

  // type convert: Java to native
//  std::vector<int8_t> encrypted_frame_payload = JavaToNativeByteArray(env, j_encrypted_frame_payload);

  // write encrypted frame data
  size_t j_length = env->GetArrayLength(jarrayOut);
  for (size_t i = 0; i < j_length; ++i) {
    encrypted_frame[i+unencrypted_bytes] = encrypted_frame_payload[i];
  }

  *bytes_written = unencrypted_bytes + j_length;

  return 0;
}

size_t GeneralFrameEncryptor::GetMaxCiphertextByteSize(
    cricket::MediaType media_type,
    size_t frame_size) {
  return frame_size + 30;
}


static jlong JNI_GeneralFrameEncryptor_GetGeneralFrameEncryptor(JNIEnv* jni) {
  return jlongFromPointer(new GeneralFrameEncryptor());
}
}   // namespace jni
}  // namespace webrtc
