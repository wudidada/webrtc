#include "sdk/android/src/jni/pc/general_frame_decryptor.h"

#include "sdk/android/generated_peerconnection_jni/GeneralFrameDecryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"
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

  for (size_t i = 0; i < unencrypted_bytes; i++) {
    frame[i] = encrypted_frame[i];
  }

  for (size_t i = unencrypted_bytes; i < encrypted_frame.size(); i++) {
    frame[i] = encrypted_frame[i];
  }

  JNIEnv* jni = AttachCurrentThreadIfNeeded();
  Java_GeneralFrameDecryptor_decrypt(jni);

  return Result(Status::kOk, encrypted_frame.size());
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