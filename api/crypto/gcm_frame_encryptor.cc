#include "api/crypto/gcm_frame_encryptor.h"

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include "rtc_base/logging.h"

namespace webrtc {

static const unsigned char gcm_key[] = {
    97, 145, 133, 203, 63, 197, 49, 232, 87, 159, 169, 200, 59, 195, 77, 75, 150, 173, 189, 232, 44, 39, 8, 149, 250, 6, 238, 170, 255, 17, 110, 107
};

private:
  std::vector<uint8_t> key_bytes;

public:
GCMFrameEncryptor::GCMFrameEncryptor() {
    RTC_LOG(LS_VERBOSE) << "XXX GCMFrameEncryptor";
}

private:
unsigned char* aes_gcm_encrypt(unsigned char *gcm_pt,
                                size_t plaintext_len,
                                unsigned char *iv,
                                unsigned char *aad,
                                int aad_len,
                                size_t &ciphertext_len) {
   int myUniqueId = rand();

   // RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt1 " << frame.size();

    int len;

    unsigned char *tag  = (unsigned char*) malloc(3024 * sizeof(unsigned char));;

    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt3";

    EVP_CIPHER_CTX *ctx;
  //  int outlen;
    unsigned char *outbuf = (unsigned char*) malloc(3024 * sizeof(unsigned char));

    if(!(ctx = EVP_CIPHER_CTX_new())) {
      RTC_LOG(LS_VERBOSE) << "XXX encryption new error------------------------";
    }

  RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt4";
    /* Set cipher type and mode */
    if (1 !=  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
       RTC_LOG(LS_VERBOSE) << "XXX encryption init error------------------------";
    }

  RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt5";
    /* Set IV length if default 96 bits is not appropriate */
    //EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);

  RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt6";
    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, iv)) {
      RTC_LOG(LS_VERBOSE) << "XXX encryption setting IV error------------------------";
    }

    /* Zero or more calls to specify any AAD */
  EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

  RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt7";
    /* Encrypt plaintext */
    if (1 != EVP_EncryptUpdate(ctx, outbuf, &len, gcm_pt, plaintext_len)) {
        RTC_LOG(LS_VERBOSE) << "XXX encryption error------------------------";
    }

  ciphertext_len = len;

   RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt8";
    /* Output encrypted block */
    /* Finalise: note get no output for GCM */
    if (1 != EVP_EncryptFinal_ex(ctx, outbuf + len, &len)) {
        RTC_LOG(LS_VERBOSE) << "XXX encryption final error------------------------";
    }

    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt9";
    /* Get tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) {
      RTC_LOG(LS_VERBOSE) << "XXX encryption tag error------------------------";
    } 
    /* Output tag */

    EVP_CIPHER_CTX_free(ctx);
    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt10";
    
   /* int lenght = 0;
    for (size_t i = 0; i < sizeof(outbuf); i++) {
        if(outbuf[i] != 0) {
            lenght = i;
        } 
    }*/

  //  RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt frame size " << sizeof(frame);
  //  RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt outbuf length " << lenght;
  //  RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt outbuf size " << sizeof(outbuf);
    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt outlen " << myUniqueId << " " << len;
    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt ciphertext_len " << myUniqueId << " " << ciphertext_len;

    for (size_t i = 0; i < 16; i++) {
          outbuf[ciphertext_len + i] = tag[i];
    }

    ciphertext_len += 16;

   /* RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt ciphertext_len1" << myUniqueId << " " << ciphertext_len;
    for (size_t i = 0; i < ciphertext_len; i++) {
          RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt myOutbuf " << myUniqueId << " " << i << " " << outbuf[i];
    }*/

    return outbuf;
}

public:
int GCMFrameEncryptor::Encrypt(cricket::MediaType media_type,
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

  std::vector<uint8_t> frame_header;
  for (size_t i = 0; i < unencrypted_bytes; i++) {
       encrypted_frame[i] = frame[i];
       frame_header.push_back(encrypted_frame[i]);
  }
  
  std::vector<uint8_t> iv = { 74, 70, 114, 97, 109, 101, 69, 110, 99, 114, 121, 112 };

  unsigned char gcm_pt[frame.size() - unencrypted_bytes];

  for (size_t i = 0; i < frame.size() - unencrypted_bytes; i++) {
       gcm_pt[i] = frame[i + unencrypted_bytes];
      // RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt2 " << i << " " << frame[i];
       //gcm_pt[i] = i;
  }

  size_t ciphertext_len;
  unsigned char *outbuf = aes_gcm_encrypt(gcm_pt, frame.size() - unencrypted_bytes, &iv[0], &frame_header[0], unencrypted_bytes, ciphertext_len);

  //unsigned char decryptedtext123[encrypted_frame.size()];
  //new_decrypt(outbuf, ciphertext_len, &iv[0], decryptedtext123);

  for (size_t i = 0; i < ciphertext_len; i++) {
      encrypted_frame[unencrypted_bytes + i] = outbuf[i];
  }
  
  size_t iv_start = unencrypted_bytes + ciphertext_len;
  RTC_LOG(LS_VERBOSE) << "XXX iv_start " << iv_start; 
  RTC_LOG(LS_VERBOSE) << "XXX unencrypted_bytes " << unencrypted_bytes; 
  RTC_LOG(LS_VERBOSE) << "XXX ciphertext_len " << ciphertext_len; 
  RTC_LOG(LS_VERBOSE) << "XXX frame size " << frame.size(); 

  for (size_t i = 0; i < iv.size(); i++) {
    encrypted_frame[iv_start + i] = iv[i];
  }

  encrypted_frame[iv_start + iv.size()] = iv.size();

  *bytes_written = encrypted_frame.size();

  /*for (size_t i = 0; i <  encrypted_frame.size(); i++) {
      RTC_LOG(LS_VERBOSE) << "XXX ncrypted_frame[iv_start + i] " << i << " " << encrypted_frame[i];
  }*/

  return 0;
}

size_t GCMFrameEncryptor::GetMaxCiphertextByteSize(
    cricket::MediaType media_type,
    size_t frame_size) {

  return frame_size + 30;
}
}  
