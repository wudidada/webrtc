#include "api/crypto/simple_frame_encryptor.h"

#include <stdio.h>

#include "rtc_base/logging.h"

namespace webrtc {

SimpleFrameEncryptor::SimpleFrameEncryptor() {
  RTC_LOG(LS_VERBOSE) << "XXX SimpleFrameEncryptor " << this->key_bytes.size();
  /*this->key_bytes = { 97,  145, 133, 203, 63,  197, 49,  232, 87,  159, 169,
                     200, 59,  195, 77,  75,  150, 173, 189, 232, 44,  39,
                     8,   149, 250, 6,   238, 170, 255, 17,  110, 107 };*/
   
}

int SimpleFrameEncryptor::Encrypt(cricket::MediaType media_type,
                               uint32_t ssrc,
                               rtc::ArrayView<const uint8_t> additional_data,
                               rtc::ArrayView<const uint8_t> frame,
                               rtc::ArrayView<uint8_t> encrypted_frame,
                               size_t* bytes_written) {
  RTC_LOG(LS_VERBOSE) << "XXX encrypting";
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
    encrypted_frame[i] = ~frame[i];
  }

  *bytes_written = encrypted_frame.size();
  RTC_LOG(LS_VERBOSE) << "simple encrypt: " << encrypted_frame.size();
  return 0;
}

size_t SimpleFrameEncryptor::GetMaxCiphertextByteSize(
    cricket::MediaType media_type,
    size_t frame_size) {
  return frame_size + 30;
}

void SimpleFrameEncryptor::SetKey(std::vector<uint8_t> key_bytes) {
  RTC_LOG(LS_VERBOSE) << "XXX settingKey1 " << key_bytes.size();
  RTC_LOG(LS_VERBOSE) << "XXX settingKey12 " << this->key_bytes.size();

//  this->key_bytes.clear();
//
//  for (size_t i = 0; i < key_bytes.size(); i++) {
//    this->key_bytes.push_back(key_bytes[i]);
//  }
  /*RTC_LOG(LS_VERBOSE) << "XXX settingKey122 " << this->key_bytes.size();
  std::vector<uint8_t>::iterator it;
  it = key_bytes.begin();
  this->key_bytes.assign(it, key_bytes.end());*/

//  RTC_LOG(LS_VERBOSE) << "XXX settingKey13 " << this->key_bytes.size();
//  RTC_LOG(LS_VERBOSE) << "XXX settingKey2";
}
}  // namespace webrtc
