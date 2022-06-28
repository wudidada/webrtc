#include "api/crypto/gcm_frame_decryptor.h"

#include <stddef.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <vector>
#include "rtc_base/logging.h"

namespace webrtc {

 GCMFrameDecryptor::GCMFrameDecryptor(std::vector<uint8_t> key_bytes) {
      this->key_bytes = key_bytes;
      RTC_LOG(LS_VERBOSE) << "XXX GCMFrameDecryptor";
     /* for (size_t i = 0; i < key_bytes.size(); i++) {
            RTC_LOG(LS_VERBOSE) << "XXX key_bytes ------------------------ " << i <<" "<< key_bytes[i];
      }*/
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

    for (int i = 0 ; i < ciphertext_len; i++) {
       // RTC_LOG(LS_VERBOSE) << "XXX decryption initial------------------------" << myUniqueId<< " " << i << " " << ciphertext[i];
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

GCMFrameDecryptor::Result GCMFrameDecryptor::Decrypt(
    cricket::MediaType media_type,
    const std::vector<uint32_t>& csrcs,
    rtc::ArrayView<const uint8_t> additional_data,
    rtc::ArrayView<const uint8_t> encrypted_frame,
    rtc::ArrayView<uint8_t> frame) {

  RTC_LOG(LS_VERBOSE) << "XXX media_type" << media_type;
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

  //RTC_LOG(LS_VERBOSE) << "XXX decrypting ------------------------------------------------------------------------";
  //RTC_LOG(LS_VERBOSE) << "XXX unencrypted_bytes ------------------------" << unencrypted_bytes;

  // Unencrypted
  for (size_t i = 0; i < unencrypted_bytes; i++) {
    frame[i] = encrypted_frame[i];
  }

  // Frame trailer
  size_t frame_trailer_size = 2;
  std::vector<uint8_t> frame_trailer;
  frame_trailer.reserve(frame_trailer_size);
  frame_trailer.push_back(encrypted_frame[encrypted_frame.size() - 2]);//IV_LENGHT
  frame_trailer.push_back(encrypted_frame[encrypted_frame.size() - 1]);
  
  // IV
  size_t iv_lenght = frame_trailer[0];
  size_t iv_start = encrypted_frame.size() - frame_trailer_size - iv_lenght;
 // RTC_LOG(LS_VERBOSE) << "XXX frame size ------------------------" <<  encrypted_frame.size();
 // RTC_LOG(LS_VERBOSE) << "XXX frame_trailer_size ------------------------" <<  frame_trailer_size;
 // RTC_LOG(LS_VERBOSE) << "XXX iv_lenght ------------------------" <<  iv_lenght;
//  RTC_LOG(LS_VERBOSE) << "XXX iv_start1 ------------------------" <<  iv_start;

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
    int decryptedtext_len;//, ciphertext_len;
   /* ciphertext_len = gcm_encrypt ( &plaintext123[0], 
                                    plaintext123.size(), 
                                    fixed_web_key, 
                                    iv123,
                                  ciphertext123); */
   
    //decryptedtext_len = new_decrypt(ciphertext123, ciphertext_len, gcm_key1, &iv1[0], decryptedtext123);
   /*  for (size_t i = 0; i < this->key_bytes.size(); i++) {
            RTC_LOG(LS_VERBOSE) << "XXX key_bytes ------------------------ " << i <<" "<< this->key_bytes[i];
  }*/
 /* for(size_t i = 0; i < iv.size(); i++) {
        RTC_LOG(LS_VERBOSE) << "XXX iv" << i << " " << iv[i];
  }*/

  //std::vector<uint8_t> new_iv = { 74, 70, 114, 97, 109, 101, 69, 110, 99, 114, 121, 112 };
  decryptedtext_len = new_decrypt(&payload[0], payload_lenght, &this->key_bytes[0], &iv[0], decryptedtext123);
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
      for (unsigned char i = 0; i < decryptedtext_len; i++) {
        frame[i + unencrypted_bytes] = decryptedtext123[i];
      }

     /* for (size_t i = 0; i < frame.size(); i++) {
        RTC_LOG(LS_VERBOSE) << "XXX encryption final------------------------" << " " << i << " " << frame[i];
      }*/

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