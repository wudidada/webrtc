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
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    int tag_offset = ciphertext_len-16;

    int myUniqueId = rand();

    for (size_t i = 0 ; i < 32; i++) {
      
    }

    for (size_t i = 0 ; i < 12; i++) {
     // RTC_LOG(LS_VERBOSE) << "XXX decryption iv------------------------" << myUniqueId<< " " << i << " " << iv[i];
    }

    for (size_t i = 0 ; i < ciphertext_len; i++) {
        RTC_LOG(LS_VERBOSE) << "XXX decryption initial------------------------" << myUniqueId<< " " << i << " " << ciphertext[i];
    }


     if(!(ctx = EVP_CIPHER_CTX_new())) {
     }


     if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        
     }
     
     if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
    	
     }

     if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, tag_offset)) {
    
     }

     plaintext_len = len;

     if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ciphertext + tag_offset)) {
    	
     }

     int rv = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
     if(1 != rv) {
	      RTC_LOG(LS_VERBOSE) << "XXX decryption final error------------------------" << myUniqueId;
        plaintext_len = -1;
     } else {
       RTC_LOG(LS_VERBOSE) << "XXX decryption final success------------------------";
     }

     printf("We did it %d\n", plaintext_len);

     /*for (size_t i = 0 ; i < plaintext_len; i++) {
         RTC_LOG(LS_VERBOSE) << "XXX decryption final------------------------" << myUniqueId<< " " << i << " " << plaintext[i];
     }*/

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
      RTC_LOG(LS_VERBOSE) << "XXX encryption initial1------------------------------------------------------------------------" << myUniqueId<< " " << i << " " << plaintext[i];
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

    /*for (size_t i =0 ; i < ciphertext_len + 16; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX encryption final------------------------" << myUniqueId<< " " << i << " " << ciphertext[i];
    }*/


    return ciphertext_len + 16;
}

GCMFrameDecryptor::Result GCMFrameDecryptor::Decrypt(
    cricket::MediaType media_type,
    const std::vector<uint32_t>& csrcs,
    rtc::ArrayView<const uint8_t> additional_data,
    rtc::ArrayView<const uint8_t> encrypted_frame,
    rtc::ArrayView<uint8_t> frame) {

  RTC_LOG(LS_VERBOSE) << "XXX decrypting ------------------------------------------------------------------------";

  for (size_t i = 0; i < encrypted_frame.size(); i++) {
        frame[i] = encrypted_frame[i];
  }
  
  return Result(Status::kOk, encrypted_frame.size());
}

size_t GCMFrameDecryptor::GetMaxPlaintextByteSize(
    cricket::MediaType media_type,
    size_t encrypted_frame_size) {
 return encrypted_frame_size;
}

}