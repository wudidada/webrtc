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

 std::string getOpenSSLError()
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}

int new_decrypt(unsigned char *ciphertext, 
                int ciphertext_len, 
                unsigned char *key,
                unsigned char *iv, 
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int myUniqueId = rand();
    int len;

    int plaintext_len;

     int tag_offset = ciphertext_len-16;

    for (size_t i =0 ; i < ciphertext_len; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX decrypting initial------------------------" << myUniqueId<< " " << i << " " << ciphertext[i];
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
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
         RTC_LOG(LS_VERBOSE) << "XXX decrypting error 22------------------------";

    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        RTC_LOG(LS_VERBOSE) << "XXX decrypting error 221------------------------";

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
   // if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
   //      RTC_LOG(LS_VERBOSE) << "XXX decrypting error 222------------------------";
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, tag_offset))
         RTC_LOG(LS_VERBOSE) << "XXX decrypting error 23------------------------";
    plaintext_len = len;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ciphertext + tag_offset)) {
        RTC_LOG(LS_VERBOSE) << "XXX decrypting error 231------------------------";
    }

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    int rv = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if(1 != rv) {
        std::string a = getOpenSSLError();
        RTC_LOG(LS_VERBOSE) << "XXX1 decrypting error 241------------------------" << a;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    RTC_LOG(LS_VERBOSE) << "XXX decrht plaintext_len------------------------" << plaintext_len;
    RTC_LOG(LS_VERBOSE) << "XXX decrht rv------------------------" << rv;

    for (size_t i =0 ; i < plaintext_len; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX decryption final------------------------" << myUniqueId<< " " << i << " " << plaintext[i];
    }
    return plaintext_len;
}

int gcm_encrypt(unsigned char *plaintext, 
                int plaintext_len,
                unsigned char *key,
                unsigned char *iv, 
                unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    int myUniqueId = rand();
    for (size_t i = 0 ; i < plaintext_len; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX encryption initial1------------------------" << myUniqueId<< " " << i << " " << plaintext[i];
    }

    for (size_t i = 0; i < strlen ((char *)key); i++) {
      RTC_LOG(LS_VERBOSE) << "XXX encryption key1------------------------" << key[i];
    }

    RTC_LOG(LS_VERBOSE) << "XXX decrypting iv lenght------------------------" << strlen ((char *)iv);
    for (size_t i = 0; i < strlen ((char *)iv); i++) {
      RTC_LOG(LS_VERBOSE) << "XXX encryption iv------------------------" << iv[i];
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        RTC_LOG(LS_VERBOSE) << "XXX encryting error 1------------------------";

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
       RTC_LOG(LS_VERBOSE) << "XXX encryting error 2------------------------";

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
       RTC_LOG(LS_VERBOSE) << "XXX encryting error 3------------------------";
    }

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        RTC_LOG(LS_VERBOSE) << "XXX encryting error 4------------------------";

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        RTC_LOG(LS_VERBOSE) << "XXX encryting error 5------------------------";
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        RTC_LOG(LS_VERBOSE) << "XXX encryting error 6------------------------";
    ciphertext_len += len;

    /* Get the tag */
   if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext + ciphertext_len))
       RTC_LOG(LS_VERBOSE) << "XXX encryting error 7------------------------";

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    for (size_t i =0 ; i < ciphertext_len + 16; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX encryption final------------------------" << myUniqueId<< " " << i << " " << ciphertext[i];
    }


    return ciphertext_len + 16;
}

GCMFrameDecryptor::Result GCMFrameDecryptor::Decrypt(
    cricket::MediaType media_type,
    const std::vector<uint32_t>& csrcs,
    rtc::ArrayView<const uint8_t> additional_data,
    rtc::ArrayView<const uint8_t> encrypted_frame,
    rtc::ArrayView<uint8_t> frame) {

  for (size_t i = 0; i < encrypted_frame.size(); i++) {
    frame[i] = encrypted_frame[i];
  }

  return Result(Status::kOk, frame.size());
}

size_t GCMFrameDecryptor::GetMaxPlaintextByteSize(
    cricket::MediaType media_type,
    size_t encrypted_frame_size) {
 return encrypted_frame_size;
}

}