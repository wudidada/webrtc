#include "sdk/android/src/jni/pc/general_frame_encryptor.h"

#include <stdio.h>
#include <jni.h>

#include "sdk/android/generated_peerconnection_jni/GeneralFrameEncryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"
#include "sdk/android/native_api/jni/java_types.h"

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
      unencrypted_bytes = 40;
      break;
    case cricket::MEDIA_TYPE_DATA:
      break;
    case cricket::MEDIA_TYPE_UNSUPPORTED:
      break;
  }

  // we can't sure the fix size of head
  if (frame.size() <= unencrypted_bytes) {
    for (size_t i = 0; i < frame.size(); i++) {
      encrypted_frame[i] = frame[i];
    }
    *bytes_written = frame.size();
    return 0;
  }

  // write unencrypted frame head
  for (size_t i = 0; i < frame.size(); i++) {
    encrypted_frame[i] = frame[i];
  }

  *bytes_written = frame.size();

  return 0;
}

size_t GeneralFrameEncryptor::GetMaxCiphertextByteSize(
    cricket::MediaType media_type,
    size_t frame_size) {
  return frame_size;
}


static jlong JNI_GeneralFrameEncryptor_GetGeneralFrameEncryptor(JNIEnv* jni) {
  return jlongFromPointer(new GeneralFrameEncryptor());
}
}   // namespace jni
}  // namespace webrtc
