#include "sdk/android/src/jni/pc/general_frame_encryptor.h"

#include <stdio.h>

#include "sdk/android/generated_peerconnection_jni/GeneralFrameEncryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"

#include "rtc_base/logging.h"

namespace webrtc {
namespace jni {
GeneralFrameEncryptor::GeneralFrameEncryptor() {
}

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

  for (size_t i = 0; i < unencrypted_bytes; i++) {
    encrypted_frame[i] = frame[i];
  }

  for (size_t i = unencrypted_bytes; i < frame.size(); i++) {
    encrypted_frame[i] = frame[i];
  }

  JNIEnv* jni = AttachCurrentThreadIfNeeded();
  Java_GeneralFrameEncryptor_encode(jni);

  *bytes_written = encrypted_frame.size();

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
