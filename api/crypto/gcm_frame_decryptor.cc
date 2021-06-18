#include "api/crypto/gcm_frame_decryptor.h"

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "rtc_base/logging.h"

namespace webrtc {

static const unsigned char gcm_key[] = {
    195, 130, 222, 164, 47, 57, 241, 245, 151, 138, 25, 165, 95, 71, 146, 
                 67, 189, 29, 194, 5, 9, 22, 33, 224, 139, 35, 60, 122, 146, 97, 169, 206
};

/*static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};*/

/*static const unsigned char gcm_pt[] = {
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
    0xcc, 0x2b, 0xf2, 0xa5
};*/

static const unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};

/*static const unsigned char gcm_ct[] = {
    0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
    0xb9, 0xf2, 0x17, 0x36
};*/

static const unsigned char gcm_tag[] = {
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
};

 GCMFrameDecryptor::GCMFrameDecryptor() {
      RTC_LOG(LS_VERBOSE) << "XXX GCMFrameDecryptor";
 }

unsigned char* aes_gcm_decrypt(uint8_t* encrypted_frame, uint8_t* iv) {

    int encrypted_frame_size = sizeof(encrypted_frame)/sizeof(uint8_t);
    unsigned char gcm_ct[encrypted_frame_size];
    int iv_size = sizeof(iv)/sizeof(uint8_t);

    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_decrypt encrypted_frame_size------------------------" << encrypted_frame_size;
    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_decrypt iv_size------------------------" << iv_size;

    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen, rv;
    unsigned char outbuf[1024];

    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_size, NULL);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, iv);
    /* Zero or more calls to specify any AAD */
    EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad)/sizeof(unsigned char));
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, outbuf, &outlen, gcm_ct, sizeof(gcm_ct)/sizeof(unsigned char));
    /* Output decrypted block */
    printf("Plaintext:\n");
    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(gcm_tag)/sizeof(unsigned char),
                        (void *)gcm_tag);
    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    /*
     * Print out return value. If this is not successful authentication
     * failed and plaintext is not trustworthy.
     */
    RTC_LOG(LS_VERBOSE) << "XXX decrypting success------------------------" << rv;
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");

    EVP_CIPHER_CTX_free(ctx);

    return outbuf;
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
      unencrypted_bytes = 3;
      break;
 }

  RTC_LOG(LS_VERBOSE) << "XXX decrypting------------------------";
  // Frame header
  for (size_t i = 0; i < unencrypted_bytes; i++) {
    frame[i] = encrypted_frame[i];
  }
  
  RTC_LOG(LS_VERBOSE) << "XXX decrypting------------------------1";

  // Frame trailer
  uint8_t* frame_trailer = new uint8_t[2];
  frame_trailer[0] = encrypted_frame[encrypted_frame.size() - 2]; //IV_LENGHT
  frame_trailer[1] = encrypted_frame[encrypted_frame.size() - 1]; 

  // IV
  uint8_t iv_lenght = frame_trailer[0];
  size_t frame_trailer_size = 2;
  size_t iv_start = encrypted_frame.size() - frame_trailer_size - iv_lenght - 1;
  uint8_t* iv = new uint8_t[iv_lenght];

 // RTC_LOG(LS_VERBOSE) << "XXX decrypting700------------------------" << iv_lenght;
 // RTC_LOG(LS_VERBOSE) << "XXX decrypting701------------------------" << iv_start;
 // RTC_LOG(LS_VERBOSE) << "XXX decrypting702------------------------" << frame_trailer_size;

  for (size_t i = 0; i < iv_lenght; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX decrypting7------------------------" << encrypted_frame[iv_start + i];
    iv[i] = encrypted_frame[iv_start + i];
  }

  RTC_LOG(LS_VERBOSE) << "XXX decrypting------------------------2";

  size_t payload_lenght = encrypted_frame.size() - (unencrypted_bytes + frame_trailer[0] + frame_trailer_size);

  RTC_LOG(LS_VERBOSE) << "XXX decrypting------------------------3";

  // Payload
  uint8_t* payload = new uint8_t[iv_lenght];
  for (size_t i = 0; i < payload_lenght; i++) {
    payload[i] = encrypted_frame[unencrypted_bytes + i];
  }

  unsigned char *outbuf = aes_gcm_decrypt(payload, iv);

  /*for (size_t i = 0; i < sizeof(outbuf); i++) {
    frame[i + unencrypted_bytes] = outbuf[i];
  }*/

 // RTC_LOG(LS_VERBOSE) << "XXX decrypting1------------------------" << frame.size();
 //RTC_LOG(LS_VERBOSE) << "XXX decrypting2------------------------" << sizeof(outbuf);
  RTC_LOG(LS_VERBOSE) << "XXX decrypting3------------------------" << encrypted_frame.size();
 // RTC_LOG(LS_VERBOSE) << "XXX decrypting4------------------------" << frame_trailer[0];
 // RTC_LOG(LS_VERBOSE) << "XXX decrypting5------------------------" << additional_data.size();
  RTC_LOG(LS_VERBOSE) << "XXX decrypting6------------------------" << payload_lenght;
  RTC_LOG(LS_VERBOSE) << "XXX decrypting71------------------------" << iv;

  return Result(Status::kOk, frame.size());
}

size_t GCMFrameDecryptor::GetMaxPlaintextByteSize(
    cricket::MediaType media_type,
    size_t encrypted_frame_size) {
 return encrypted_frame_size;
}

}