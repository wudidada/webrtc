#include "api/crypto/gcm_frame_decryptor.h"

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <vector>
#include "rtc_base/logging.h"

namespace webrtc {

 GCMFrameDecryptor::GCMFrameDecryptor() {
      RTC_LOG(LS_VERBOSE) << "XXX GCMFrameDecryptor";
 }

int new_decrypt(unsigned char *ciphertext, 
                int ciphertext_len, 
                unsigned char *key,
                unsigned char *iv, 
                unsigned char *plaintext,
                cricket::MediaType media_type)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    int tag_offset = ciphertext_len-16;

    int myUniqueId = rand();

    /*for (size_t i = 0 ; i < 32; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX imported key------------------------" << myUniqueId<< " " << i << " " << key[i] << ",";
    }*/

   for (size_t i = 0 ; i < 12; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX iv------------------------" << myUniqueId<< " " << i << " " << iv[i] << ",";
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) {
      RTC_LOG(LS_VERBOSE) << "XXX decryption error1";
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
         RTC_LOG(LS_VERBOSE) << "XXX decryption error2";
    }
     
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
    	 RTC_LOG(LS_VERBOSE) << "XXX decryption error3";
     }

     if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, tag_offset)) {
     RTC_LOG(LS_VERBOSE) << "XXX decryption error4";
     }

     plaintext_len = len;

     if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ciphertext + tag_offset)) {
    	 RTC_LOG(LS_VERBOSE) << "XXX decryption error5";
     }

     RTC_LOG(LS_VERBOSE) << "XXX decryption lenght------------------------" << myUniqueId<< " " << ciphertext_len << " " << media_type;
     int rv = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
     if(1 != rv) {
        RTC_LOG(LS_VERBOSE) << "XXX decryption final error------------------------" << myUniqueId << " " << media_type;
        /*for (size_t i = 0 ; i < ciphertext_len; i++) {
             RTC_LOG(LS_VERBOSE) << "XXX decryption initial error------------------------" << myUniqueId<< " " << i << " " << ciphertext[i] << ",";
        }*/

        plaintext_len = -1;
     } else {
       /*for (size_t i = 0 ; i < ciphertext_len; i++) {
             RTC_LOG(LS_VERBOSE) << "XXX decryption initial success------------------------" << myUniqueId<< " " << i << " " << ciphertext[i] << ",";
        }*/
       RTC_LOG(LS_VERBOSE) << "XXX decryption final success------------------------";
     }

     return plaintext_len;
}

GCMFrameDecryptor::Result GCMFrameDecryptor::Decrypt(
    cricket::MediaType media_type,
    const std::vector<uint32_t>& csrcs,
    rtc::ArrayView<const uint8_t> additional_data,
    rtc::ArrayView<const uint8_t> encrypted_frame,
    rtc::ArrayView<uint8_t> frame) {

 uint8_t unencrypted_bytes = 10;
 switch (media_type) {
    case cricket::MEDIA_TYPE_AUDIO:
      unencrypted_bytes = 1;
      break;
    case cricket::MEDIA_TYPE_VIDEO:
      unencrypted_bytes = 10;
      break;
 }

  // Frame header
  size_t frame_header_size = unencrypted_bytes;
  std::vector<uint8_t> frame_header;
  for (size_t i = 0; i < unencrypted_bytes; i++) {
    frame[i] = encrypted_frame[i];
    frame_header.push_back(encrypted_frame[i]);
  }

  // Frame trailer
  size_t frame_trailer_size = 2;
  std::vector<uint8_t> frame_trailer;
  frame_trailer.reserve(frame_trailer_size);
  frame_trailer.push_back(encrypted_frame[encrypted_frame.size() - 2]);//IV_LENGHT
  frame_trailer.push_back(encrypted_frame[encrypted_frame.size() - 1]);
  
  int myUniqueId = rand();
  for (size_t i = 0; i < encrypted_frame.size(); i++) {
      RTC_LOG(LS_VERBOSE) << "XXX decryption initial frame------------------------" << myUniqueId << " " << i << " " << encrypted_frame[i] << ",";
  }

  // IV
  uint8_t iv_lenght = frame_trailer[0];
  uint8_t iv_start = encrypted_frame.size() - frame_trailer_size - iv_lenght;
  std::vector<uint8_t> iv;
  iv.reserve(iv_lenght);
  for (size_t i = iv_start; i < iv_start + iv_lenght; i++) {
      iv.push_back(encrypted_frame[i]);
  }

  RTC_LOG(LS_VERBOSE) << "XXX decryption iv size------------------------" << myUniqueId << " " << iv_start << " " << iv_lenght;

  // payload
  size_t payload_lenght = encrypted_frame.size() - (unencrypted_bytes + frame_trailer[0] + frame_trailer_size);
  std::vector<uint8_t> payload;
  payload.reserve(payload_lenght);
  for (size_t i = unencrypted_bytes; i < unencrypted_bytes + payload_lenght; i++) {
    payload.push_back(encrypted_frame[i]);
  }
    unsigned char decryptedtext123[encrypted_frame.size()];
    int decryptedtext_len, ciphertext_len;
   
  std::vector<uint8_t> imported_web_key = {97, 145, 133, 203, 63, 197, 49, 232, 87, 159, 169, 200, 59, 195, 77, 75, 150, 173, 189, 232, 44, 39, 8, 149, 250, 6, 238, 170, 255, 17, 110, 107};
  decryptedtext_len = new_decrypt(&payload[0], payload_lenght, &imported_web_key[0], &iv[0], decryptedtext123, media_type);

  if(decryptedtext_len > 0) {
      for (size_t i = 0; i < decryptedtext_len; i++) {
        frame[i + unencrypted_bytes] = decryptedtext123[i];
      }

      return Result(Status::kOk, decryptedtext_len + unencrypted_bytes);
  } else {
    for (size_t i = 0; i < encrypted_frame.size(); i++) {
        frame[i] = encrypted_frame[i];
    }
      return Result(Status::kOk, encrypted_frame.size());
  }
}

size_t GCMFrameDecryptor::GetMaxPlaintextByteSize(
    cricket::MediaType media_type,
    size_t encrypted_frame_size) {
 return encrypted_frame_size;
}

}