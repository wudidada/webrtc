#include "api/crypto/gcm_frame_encryptor.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdio.h>

#include "rtc_base/logging.h"

namespace webrtc {

GCMFrameEncryptor::GCMFrameEncryptor() {}

unsigned char* encrypt(unsigned char* key,
                       unsigned char* plaintext,
                       size_t plaintext_len,
                       unsigned char* iv,
                       unsigned char* aad,
                       int aad_len,
                       size_t& ciphertext_len) {
  int len;

  unsigned char* tag = (unsigned char*)malloc(3024 * sizeof(unsigned char));

  EVP_CIPHER_CTX* ctx;
  unsigned char* ciphertext =
      (unsigned char*)malloc(3024 * sizeof(unsigned char));

  if (!(ctx = EVP_CIPHER_CTX_new())) {
  }

  /* Set cipher type and mode */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
  }

  /* Initialise key and IV */
  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
  }

  /* Zero or more calls to specify any AAD */
  EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

  /* Encrypt plaintext */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
  }

  ciphertext_len = len;

  /* Output encrypted block */
  /* Finalise: note get no output for GCM */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
  }

  /* Get tag */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) {
  }

  EVP_CIPHER_CTX_free(ctx);

  for (size_t i = 0; i < 16; i++) {
    ciphertext[ciphertext_len + i] = tag[i];
  }

  ciphertext_len += 16;

  return ciphertext;
}

int GCMFrameEncryptor::Encrypt(cricket::MediaType media_type,
                               uint32_t ssrc,
                               rtc::ArrayView<const uint8_t> additional_data,
                               rtc::ArrayView<const uint8_t> frame,
                               rtc::ArrayView<uint8_t> encrypted_frame,
                               size_t* bytes_written) {
  RTC_LOG(LS_VERBOSE) << "XXX encrypting";

  try {
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

    std::vector<uint8_t> frame_header;
    for (size_t i = 0; i < unencrypted_bytes; i++) {
      encrypted_frame[i] = frame[i];
      frame_header.push_back(encrypted_frame[i]);
    }

    std::vector<uint8_t> iv = {74, 70,  114, 97,  109, 101,
                               69, 110, 99,  114, 121, 112};

    unsigned char plaintext[frame.size() - unencrypted_bytes];

    for (size_t i = 0; i < frame.size() - unencrypted_bytes; i++) {
      plaintext[i] = frame[i + unencrypted_bytes];
    }

    size_t ciphertext_len;
    unsigned char* ciphertext = encrypt(
        &this->key_bytes[0], plaintext, frame.size() - unencrypted_bytes,
        &iv[0], &frame_header[0], unencrypted_bytes, ciphertext_len);

    for (size_t i = 0; i < ciphertext_len; i++) {
      encrypted_frame[unencrypted_bytes + i] = ciphertext[i];
    }

    size_t iv_start = unencrypted_bytes + ciphertext_len;

    for (size_t i = 0; i < iv.size(); i++) {
      encrypted_frame[iv_start + i] = iv[i];
    }

    encrypted_frame[iv_start + iv.size()] = iv.size();

    *bytes_written = encrypted_frame.size();
  } catch (int myNum) {
    RTC_LOG(LS_VERBOSE) << "XXX encrypting exception";
  }

  return 0;
}

size_t GCMFrameEncryptor::GetMaxCiphertextByteSize(
    cricket::MediaType media_type,
    size_t frame_size) {
  return frame_size + 30;
}

void GCMFrameEncryptor::SetKey(std::vector<uint8_t> key_bytes) {
  this->key_bytes = key_bytes;
  RTC_LOG(LS_VERBOSE) << "XXX settingKey";
}
}  // namespace webrtc
