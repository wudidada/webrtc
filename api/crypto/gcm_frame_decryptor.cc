#include "api/crypto/gcm_frame_decryptor.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdio.h>

#include <vector>

namespace webrtc {

GCMFrameDecryptor::GCMFrameDecryptor(std::vector<uint8_t> key_bytes) {
  this->key_bytes = key_bytes;
}

int decrypt(unsigned char* key,
            unsigned char* ciphertext,
            int ciphertext_len,
            unsigned char* iv,
            unsigned char* aad,
            int aad_len,
            unsigned char* plaintext) {
  EVP_CIPHER_CTX* ctx;

  int len;

  int plaintext_len;

  int tag_offset = ciphertext_len - 16;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
  }

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
  }

  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
  }

  if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
  }

  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, tag_offset)) {
  }

  plaintext_len = len;

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                           ciphertext + tag_offset)) {
  }

  int rv = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  if (1 != rv) {
    plaintext_len = -1;
  }

  return plaintext_len;
}

GCMFrameDecryptor::Result GCMFrameDecryptor::Decrypt(
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

  std::vector<uint8_t> frame_header;
  for (size_t i = 0; i < unencrypted_bytes; i++) {
    frame[i] = encrypted_frame[i];
    frame_header.push_back(encrypted_frame[i]);
  }

  // Frame trailer
  size_t frame_trailer_size = 2;
  std::vector<uint8_t> frame_trailer;
  frame_trailer.reserve(frame_trailer_size);
  frame_trailer.push_back(
      encrypted_frame[encrypted_frame.size() - 2]);  // IV_LENGHT
  frame_trailer.push_back(encrypted_frame[encrypted_frame.size() - 1]);

  // IV
  size_t iv_lenght = frame_trailer[0];
  size_t iv_start = encrypted_frame.size() - frame_trailer_size - iv_lenght;

  std::vector<uint8_t> iv;
  iv.reserve(iv_lenght);
  for (size_t i = iv_start; i < iv_start + iv_lenght; i++) {
    iv.push_back(encrypted_frame[i]);
  }

  size_t payload_lenght =
      encrypted_frame.size() -
      (unencrypted_bytes + frame_trailer[0] + frame_trailer_size);
  std::vector<uint8_t> payload;
  payload.reserve(payload_lenght);
  for (size_t i = unencrypted_bytes; i < unencrypted_bytes + payload_lenght;
       i++) {
    payload.push_back(encrypted_frame[i]);
  }
  unsigned char decryptedtext[encrypted_frame.size()];
  int decryptedtext_len;

  decryptedtext_len =
      decrypt(&this->key_bytes[0], &payload[0], payload_lenght, &iv[0],
              &frame_header[0], unencrypted_bytes, decryptedtext);

  if (decryptedtext_len > 0) {
    for (unsigned char i = 0; i < decryptedtext_len; i++) {
      frame[i + unencrypted_bytes] = decryptedtext[i];
    }

    return Result(Status::kOk, decryptedtext_len + unencrypted_bytes);
  } else {
    for (size_t i = 0; i < encrypted_frame.size(); i++) {
      frame[i] = encrypted_frame[i];
    }
    return Result(Status::kOk, encrypted_frame.size());
  }
}

size_t GCMFrameDecryptor::GetMaxPlaintextByteSize(cricket::MediaType media_type,
                                                  size_t encrypted_frame_size) {
  return encrypted_frame_size;
}

void GCMFrameEncryptor::SetKey(std::vector<uint8_t> key_bytes) {
  this->key_bytes = key_bytes;
}
}  // namespace webrtc