#include "sdk/android/src/jni/pc/general_frame_decryptor.h"

#include "sdk/android/generated_peerconnection_jni/GeneralFrameDecryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"
#include "sdk/android/native_api/jni/java_types.h"

#include <stddef.h>
#include <stdio.h>

#include <vector>

namespace webrtc {
namespace jni {
GeneralFrameDecryptor::GeneralFrameDecryptor() {}

GeneralFrameDecryptor::Result GeneralFrameDecryptor::Decrypt(
    cricket::MediaType media_type,
    const std::vector<uint32_t>& csrcs,
    rtc::ArrayView<const uint8_t> additional_data,
    rtc::ArrayView<const uint8_t> encrypted_frame,
    rtc::ArrayView<uint8_t> frame) {
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
    frame[i] = encrypted_frame[i];
  }

  JNIEnv* env = AttachCurrentThreadIfNeeded();

  // type convert: native to Java
  rtc::ArrayView<const uint8_t> encrypted_frame_payload = encrypted_frame.subview(unencrypted_bytes);
  ScopedJavaLocalRef<jbyteArray> j_encrypted_frame_payload(env,
                                                 env->NewByteArray(encrypted_frame_payload.size()));
  env->SetByteArrayRegion(j_encrypted_frame_payload.obj(), 0, encrypted_frame_payload.size(), encrypted_frame_payload.data());

  // call Java side function
  ScopedJavaLocalRef<jbyteArray> j_frame_payload =
      Java_GeneralFrameDecryptor_decrypt(env, j_encrypted_frame_payload);

  // type convert: Java to native
  std::vector<int8_t> frame_payload = JavaToNativeByteArray(env, j_frame_payload);

  // write encrypted frame data
  size_t j_length = frame_payload.size();
  for (size_t i = 0; i < j_length; ++i) {
    frame[i+unencrypted_bytes] = frame_payload[i];
  }

  return Result(Status::kOk, unencrypted_bytes + j_length);
}

size_t GeneralFrameDecryptor::GetMaxPlaintextByteSize(cricket::MediaType media_type,
                                                      size_t encrypted_frame_size) {
  return encrypted_frame_size;
}

static jlong JNI_GeneralFrameDecryptor_GetGeneralFrameDecryptor(JNIEnv* jni) {
  return jlongFromPointer(new GeneralFrameDecryptor());
}
}  // namespace jni
}  // namespace webrtc