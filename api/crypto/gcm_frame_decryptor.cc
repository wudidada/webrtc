#include "api/crypto/gcm_frame_decryptor.h"

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <vector>
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

/*static const unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};*/

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

std::vector<uint8_t> aes_gcm_decrypt(std::vector<uint8_t> encrypted_frame, 
                               std::vector<uint8_t> iv) {

    int encrypted_frame_size = encrypted_frame.size();
    unsigned char gcm_ct[encrypted_frame_size];
    int iv_size = iv.size();

    //RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_decrypt encrypted_frame_size------------------------" << encrypted_frame_size;
    //RTC_LOG(LS_VERBOSE) << "XXX aes_gcm_decrypt iv_size------------------------" << iv_size;

    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen, rv;
    std::vector<uint8_t> outbuf;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        RTC_LOG(LS_VERBOSE) << "XXX decrypting error1------------------------";
    }


    /* Select cipher */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
       RTC_LOG(LS_VERBOSE) << "XXX decrypting error2------------------------";
    }

    /* Specify key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, iv.data())) {
      RTC_LOG(LS_VERBOSE) << "XXX decrypting error3------------------------";
    }
    /* Zero or more calls to specify any AAD */
   // EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad)/sizeof(unsigned char));
    
    /* Decrypt plaintext */
    if(!EVP_DecryptUpdate(ctx, &outbuf[0], &outlen, &encrypted_frame[0], encrypted_frame.size())){
      RTC_LOG(LS_VERBOSE) << "XXX decrypting error4------------------------";
    }

    /* Set expected tag value. */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,(void *)gcm_tag)) {
      RTC_LOG(LS_VERBOSE) << "XXX decrypting error5------------------------";
    }
    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, &encrypted_frame[outlen], &outlen);

    RTC_LOG(LS_VERBOSE) << "XXX decrypting success------------------------" << rv;
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");

    EVP_CIPHER_CTX_free(ctx);

    return outbuf;
}

int new_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    for (size_t i =0 ; i < ciphertext_len; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX decrypting initial------------------------" << i << " " << ciphertext[i];
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        RTC_LOG(LS_VERBOSE) << "XXX decrypting error 21------------------------";

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
         RTC_LOG(LS_VERBOSE) << "XXX decrypting error 22------------------------";

    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        RTC_LOG(LS_VERBOSE) << "XXX decrypting error 221------------------------";
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
         RTC_LOG(LS_VERBOSE) << "XXX decrypting error 23------------------------";
    plaintext_len = len;


    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        RTC_LOG(LS_VERBOSE) << "XXX decrypting error 231------------------------";
    }
    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    int rv = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if(1 != rv) {
        RTC_LOG(LS_VERBOSE) << "XXX1 decrypting error 24------------------------";
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    RTC_LOG(LS_VERBOSE) << "XXX decrht plaintext_len------------------------" << plaintext_len;
    RTC_LOG(LS_VERBOSE) << "XXX decrht rv------------------------" << rv;

    for (size_t i =0 ; i < plaintext_len; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX decryption final------------------------" << i << " " << plaintext[i];
    }
    return plaintext_len;
}

int new_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    for (size_t i =0 ; i < plaintext_len; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX encrypting initial------------------------" << i << " " << plaintext[i];
    }

    /*for (size_t i =0 ; i < 12; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX encrypting iv------------------------" << i << " " << iv[i];
    }

    for (size_t i =0 ; i < 32; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX encrypting keyv------------------------" << i << " " << key[i];
    }*/

    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        RTC_LOG(LS_VERBOSE) << "XXX encrypting error 21------------------------";

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
         RTC_LOG(LS_VERBOSE) << "XXX encrypting error 22------------------------";

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
         RTC_LOG(LS_VERBOSE) << "XXX encrypting error 23------------------------";

    RTC_LOG(LS_VERBOSE) << "XXX encrypting no error 23------------------------" << len;
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
           RTC_LOG(LS_VERBOSE) << "XXX encrypting error 24------------------------";
    }

    RTC_LOG(LS_VERBOSE) << "XXX encrypting error 24------------------------" << len;
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    RTC_LOG(LS_VERBOSE) << "XXX encrypting ciphertext_len------------------------" << ciphertext_len;

    std::string str;
    for (size_t i =0 ; i < ciphertext_len; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX encrypting final------------------------" << i << " " << ciphertext[i];
    }

    RTC_LOG(LS_VERBOSE) << "XXX encrypting final------------------------" << str;
    return ciphertext_len;
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
      unencrypted_bytes = 3;
      break;
 }

  RTC_LOG(LS_VERBOSE) << "XXX decrypting------------------------";

  return Result(Status::kOk, frame.size());
}

size_t GCMFrameDecryptor::GetMaxPlaintextByteSize(
    cricket::MediaType media_type,
    size_t encrypted_frame_size) {
 return encrypted_frame_size;
}

}