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

static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

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

unsigned char* aes_gcm_decrypt(rtc::ArrayView<const uint8_t> encrypted_frame) {

    unsigned char gcm_ct[encrypted_frame.size()];

    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen, rv;
    unsigned char outbuf[1024];

    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
    /* Zero or more calls to specify any AAD */
    EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, outbuf, &outlen, gcm_ct, sizeof(gcm_ct));
    /* Output decrypted block */
    printf("Plaintext:\n");
    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(gcm_tag),
                        (void *)gcm_tag);
    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    /*
     * Print out return value. If this is not successful authentication
     * failed and plaintext is not trustworthy.
     */
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");

    EVP_CIPHER_CTX_free(ctx);
    RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_decrypt2" << rv;

    return outbuf;
}

GCMFrameDecryptor::Result GCMFrameDecryptor::Decrypt(
    cricket::MediaType media_type,
    const std::vector<uint32_t>& csrcs,
    rtc::ArrayView<const uint8_t> additional_data,
    rtc::ArrayView<const uint8_t> encrypted_frame,
    rtc::ArrayView<uint8_t> frame) {

 uint8_t unencrypted_bytes = 4;
 switch (media_type) {
    case cricket::MEDIA_TYPE_AUDIO:
      unencrypted_bytes = 3;
      break;
    case cricket::MEDIA_TYPE_VIDEO:
      unencrypted_bytes = 4;
      break;
 }

  /*for (size_t i = 0; i < frame.size(); i++) {
    frame[i] = encrypted_frame[i];
  }*/

  for (size_t i = 0; i < unencrypted_bytes; i++) {
    frame[i] = encrypted_frame[i];
  }

  unsigned char *outbuf = aes_gcm_decrypt(encrypted_frame);

  for (size_t i = 0; i < sizeof(outbuf); i++) {
    frame[i + unencrypted_bytes] = outbuf[i];
  }

  RTC_LOG(LS_VERBOSE) << "XXX decrypting------------------------";
  RTC_LOG(LS_VERBOSE) << "XXX decrypting1------------------------" << frame.size();
  RTC_LOG(LS_VERBOSE) << "XXX decrypting2------------------------" << sizeof(outbuf);
  RTC_LOG(LS_VERBOSE) << "XXX decrypting3------------------------" << encrypted_frame.size();
  RTC_LOG(LS_VERBOSE) << "XXX decrypting4------------------------" << additional_data.size();

  return Result(Status::kOk, frame.size());
}

size_t GCMFrameDecryptor::GetMaxPlaintextByteSize(
    cricket::MediaType media_type,
    size_t encrypted_frame_size) {
 return encrypted_frame_size;
}

}