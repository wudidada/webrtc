#include "api/crypto/simple_frame_decryptor.h"

#include <stddef.h>
#include <stdio.h>

#include <vector>

#include "rtc_base/logging.h"

namespace webrtc {

SimpleFrameDecryptor::SimpleFrameDecryptor() {}

SimpleFrameDecryptor::Result SimpleFrameDecryptor::Decrypt(
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

  for (size_t i = unencrypted_bytes; i < frame.size(); i++) {
    frame[i] = ~encrypted_frame[i];
  }

  RTC_LOG(LS_VERBOSE) << "simple unencrypt: " << frame.size();
  return Result(Status::kOk, frame.size());
}

size_t SimpleFrameDecryptor::GetMaxPlaintextByteSize(cricket::MediaType media_type,
                                                  size_t encrypted_frame_size) {
  return encrypted_frame_size;
}

void SimpleFrameDecryptor::SetKey(std::vector<uint8_t> key_bytes) {
  RTC_LOG(LS_VERBOSE) << "XXX settingKey1 " << key_bytes.size();
  RTC_LOG(LS_VERBOSE) << "XXX settingKey12 " << this->key_bytes.size();
//  this->key_bytes = key_bytes;
  RTC_LOG(LS_VERBOSE) << "XXX settingKey13 " << this->key_bytes.size();
}
}  // namespace webrtc