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

 uint8_t unencrypted_bytes = 10;
 switch (media_type) {
    case cricket::MEDIA_TYPE_AUDIO:
      unencrypted_bytes = 1;
      break;
    case cricket::MEDIA_TYPE_VIDEO:
      unencrypted_bytes = 3;
      break;
 }

  RTC_LOG(LS_VERBOSE) << "XXX decrypting ------------------------------------------------------------------------";
  RTC_LOG(LS_VERBOSE) << "XXX unencrypted_bytes ------------------------" << unencrypted_bytes;

  for (size_t i = 0; i < encrypted_frame.size(); i++) {
     //RTC_LOG(LS_VERBOSE) << "XXX frame ------------------------ " << i <<" "<< encrypted_frame[i];
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
  
  // IV
  uint8_t iv_lenght = frame_trailer[0];
  uint8_t iv_start = encrypted_frame.size() - frame_trailer_size - iv_lenght;
  std::vector<uint8_t> iv;
  iv.reserve(iv_lenght);
  for (size_t i = iv_start; i < iv_start + iv_lenght; i++) {
      iv.push_back(encrypted_frame[i]);
  }

  // payload
  size_t payload_lenght = encrypted_frame.size() - (unencrypted_bytes + frame_trailer[0] + frame_trailer_size);
 // size_t payload_lenght = 5;
  std::vector<uint8_t> payload;
  payload.reserve(payload_lenght);
  for (size_t i = unencrypted_bytes; i < unencrypted_bytes + payload_lenght; i++) {
    payload.push_back(encrypted_frame[i]);
  }

    //std::vector<uint8_t> salt = { 74, 70, 114, 97, 109, 101, 69, 110, 99, 114, 121, 112, 116, 105, 111, 110, 75, 101, 121 };

    //unsigned char derivedKey[EVP_MAX_KEY_LENGTH], derivedIV[EVP_MAX_IV_LENGTH];

   /* int lenght = EVP_BytesToKey(EVP_aes_256_gcm(), EVP_sha256(), &salt[0],
                          &gcm_key1[0], 32, 1, derivedKey, derivedIV);

    for (size_t i =0 ; i < lenght; i++) {
      RTC_LOG(LS_VERBOSE) << "XXX derived kwy final------------------------" << derivedKey[i];
    }
    
     RTC_LOG(LS_VERBOSE) << "XXX newEncrypt1 lenght" << lenght;  */

    unsigned char decryptedtext123[encrypted_frame.size()];
    int decryptedtext_len, ciphertext_len;
   /* ciphertext_len = gcm_encrypt ( &plaintext123[0], 
                                    plaintext123.size(), 
                                    fixed_web_key, 
                                    iv123,
                                  ciphertext123); */
   
  std::vector<uint8_t> imported_web_key = {97, 145, 133, 203, 63, 197, 49, 232, 87, 159, 169, 200, 59, 195, 77, 75, 150, 173, 189, 232, 44, 39, 8, 149, 250, 6, 238, 170, 255, 17, 110, 107};
  //decryptedtext_len = new_decrypt(ciphertext123, ciphertext_len, gcm_key1, &iv1[0], decryptedtext123);
  decryptedtext_len = new_decrypt(&payload[0], payload_lenght, &imported_web_key[0], &iv[0], decryptedtext123);
  //decryptedtext_len = new_decrypt(&ciphertext1234[0], ciphertext1234.size(), &imported_web_key[0], iv123, decryptedtext123);
    /* Decrypt the ciphertext */
  /*  decryptedtext_len = new_decrypt(
      &payload[0], 
      payload_lenght, 
      gcm_key1, 
      &frame_header[0],
      frame_header_size,
      &iv1[0], 
      decryptedtext, 
      tag); */
    /*for(size_t i = 0; i < payload_lenght; i++) {
        RTC_LOG(LS_VERBOSE) << "XXX payload" << i << " " << payload[i];
    }*/

  if(decryptedtext_len > 0) {
      for (size_t i = 0; i < decryptedtext_len; i++) {
        frame[i + unencrypted_bytes] = decryptedtext123[i];
      }

      for (size_t i = 0; i < frame.size(); i++) {
        RTC_LOG(LS_VERBOSE) << "XXX encryption final------------------------" << " " << i << " " << frame[i];
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