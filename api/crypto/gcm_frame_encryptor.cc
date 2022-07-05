#include "api/crypto/gcm_frame_encryptor.h"

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include "rtc_base/logging.h"

namespace webrtc {

static const unsigned char gcm_key[] = {
    195, 130, 222, 164, 47, 57, 241, 245, 151, 138, 25, 165, 95, 71, 146, 
     67, 189, 29, 194, 5, 9, 22, 33, 224, 139, 35, 60, 122, 146, 97, 169, 206
};

static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

/*static const unsigned char gcm_pt[] = {
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
    0xcc, 0x2b, 0xf2, 0xa5
};*/

/*static const unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};

static const unsigned char gcm_ct[] = {
    0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
    0xb9, 0xf2, 0x17, 0x36
};

static const unsigned char gcm_tag[] = {
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
};*/

GCMFrameEncryptor::GCMFrameEncryptor() {
    RTC_LOG(LS_VERBOSE) << "XXX GCMFrameEncryptor";
}

 unsigned char* aes_gcm_encrypt(rtc::ArrayView<const uint8_t> frame)
{
    unsigned char gcm_pt[frame.size()];

    for (size_t i = 0; i < frame.size(); i++) {
       gcm_pt[i] = frame[i];
    }

    EVP_CIPHER_CTX *ctx;
    int outlen;
    unsigned char *outbuf = (unsigned char*) malloc(1024 * sizeof(unsigned char));

    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
    /* Zero or more calls to specify any AAD */
    //EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, outbuf, &outlen, gcm_pt, sizeof(gcm_pt));
    /* Output encrypted block */
    printf("Ciphertext:\n");
    /* Finalise: note get no output for GCM */
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
    /* Output tag */

    EVP_CIPHER_CTX_free(ctx);
    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt2";
    
    int lenght = 0;
    for (size_t i = 0; i < sizeof(outbuf); i++) {
        if(outbuf[i] != 0) {
            lenght = i;
        } 
    }

    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt frame size" << sizeof(frame);
    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt outbuf length" << lenght;
    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt outbuf size" << sizeof(outbuf);
    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_encrypt outlen" << outlen;

    return outbuf;
}

// FrameEncryptorInterface implementation
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

  for (size_t i = 0; i < unencrypted_bytes; i++) {
       encrypted_frame[i] = frame[i];
  }
  
  unsigned char *outbuf = aes_gcm_encrypt(frame);

  for (size_t i = 0; i < sizeof(outbuf); i++) {
       encrypted_frame[unencrypted_bytes + i] = outbuf[i];
  }

  std::vector<uint8_t> new_iv = { 74, 70, 114, 97, 109, 101, 69, 110, 99, 114, 121, 112 };
  
  size_t iv_start = unencrypted_bytes + sizeof(outbuf);

  for (size_t i = 0; i < iv.size(); i++) {
    encrypted_frame[iv_start + i] = iv[i];
  }

  encrypted_frame[iv_start + iv.size()] = iv.size();

  *bytes_written = encrypted_frame.size();

  return 0;
}

size_t GCMFrameEncryptor::GetMaxCiphertextByteSize(
    cricket::MediaType media_type,
    size_t frame_size) {
  return frame_size;
}
}  
