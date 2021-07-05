#include "api/crypto/gcm_frame_decryptor.h"

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <vector>
#include "rtc_base/logging.h"

#include <iostream>
#include <string>
#include <memory>
#include <limits>
#include <stdexcept>

#include <openssl/rand.h>

namespace webrtc {

static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;

template <typename T>
struct zallocator
{
public:
    typedef T value_type;
    typedef value_type* pointer;
    typedef const value_type* const_pointer;
    typedef value_type& reference;
    typedef const value_type& const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;

    pointer address (reference v) const {return &v;}
    const_pointer address (const_reference v) const {return &v;}

    pointer allocate (size_type n, const void* hint = 0) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T))
            RTC_LOG(LS_VERBOSE) << "XXX bad alloc";
        return static_cast<pointer> (::operator new (n * sizeof (value_type)));
    }

    void deallocate(pointer p, size_type n) {
        OPENSSL_cleanse(p, n*sizeof(T));
        ::operator delete(p); 
    }
    
    size_type max_size() const {
        return std::numeric_limits<size_type>::max() / sizeof (T);
    }
    
    template<typename U>
    struct rebind
    {
        typedef zallocator<U> other;
    };

    void construct (pointer ptr, const T& val) {
        new (static_cast<T*>(ptr) ) T (val);
    }

    void destroy(pointer ptr) {
        static_cast<T*>(ptr)->~T();
    }

#if __cpluplus >= 201103L
    template<typename U, typename... Args>
    void construct (U* ptr, Args&&  ... args) {
        ::new (static_cast<void*> (ptr) ) U (std::forward<Args> (args)...);
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }
#endif
};

typedef unsigned char byte;
typedef std::basic_string<char, std::char_traits<char>, zallocator<char> > secure_string;
using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

void gen_params(byte key[KEY_SIZE], byte iv[BLOCK_SIZE]);
void aes_encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ptext, secure_string& ctext);
void aes_decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ctext, secure_string& rtext);

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
                unsigned char *aad, 
                int aad_len,
                unsigned char *iv, 
                unsigned char *plaintext, 
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int myUniqueId = rand();
    int len;

    int plaintext_len;

    for (size_t i = 0 ; i < ciphertext_len; i++) {
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
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
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
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
         RTC_LOG(LS_VERBOSE) << "XXX decrypting error 23------------------------";
    plaintext_len = len;

    //if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
      //  RTC_LOG(LS_VERBOSE) << "XXX decrypting error 231------------------------";
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
  RTC_LOG(LS_VERBOSE) << "XXX unencrypted_bytes ------------------------" << unencrypted_bytes;
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
  uint8_t iv_start = encrypted_frame.size() - frame_trailer_size - iv_lenght - 1;
  std::vector<uint8_t> iv;
  iv.reserve(iv_lenght);
  for (size_t i = iv_start; i < iv_start + iv_lenght; i++) {
      iv.push_back(encrypted_frame[i]);
  }

  // payload
  size_t payload_lenght = encrypted_frame.size() - (unencrypted_bytes + frame_trailer[0] + frame_trailer_size);
  std::vector<uint8_t> payload;
  payload.reserve(payload_lenght);
  for (size_t i = unencrypted_bytes; i < unencrypted_bytes + payload_lenght; i++) {
    payload.push_back(encrypted_frame[i]);
  }

  std::vector<uint8_t> plaintext;

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[400];
    unsigned char tag[400];

    int decryptedtext_len;

    unsigned char gcm_key1[] = {
                 195, 130, 222, 164, 47, 57, 241, 245, 151, 138, 25, 165, 95, 71, 146, 
                 67, 189, 29, 194, 5, 9, 22, 33, 224, 139, 35, 60, 122, 146, 97, 169, 206
    };

    std::vector<uint8_t> iv1 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

    RTC_LOG(LS_VERBOSE) << "XXX newEncrypt------------------------";

    // Load the necessary cipher
    EVP_add_cipher(EVP_aes_256_cbc());

    // plaintext, ciphertext, recovered text
    secure_string ptext = "Now is the time for all good men to come to the aide of their country";
    secure_string ctext, rtext;

    byte key[KEY_SIZE], iv[BLOCK_SIZE];
    gen_params(key, iv);
  
    aes_encrypt(key, iv, ptext, ctext);
    aes_decrypt(key, iv, ctext, rtext);
    
    OPENSSL_cleanse(key, KEY_SIZE);
    OPENSSL_cleanse(iv, BLOCK_SIZE);

    RTC_LOG(LS_VERBOSE) << "XXX Original message: " << ptext;
    RTC_LOG(LS_VERBOSE) << "XXX Recovered message" << rtext;

    /* Decrypt the ciphertext */
   /* decryptedtext_len = new_decrypt(
      &payload[0], 
      payload_lenght, 
      gcm_key1, 
      &frame_header[0],
      frame_header_size,
      &iv1[0], 
      decryptedtext, 
      tag);*/
    /*for(size_t i = 0; i < payload_lenght; i++) {
        RTC_LOG(LS_VERBOSE) << "XXX payload" << i << " " << payload[i];
    }*/

  for (size_t i = 0; i < decryptedtext_len; i++) {
    frame[i + unencrypted_bytes] = decryptedtext[unencrypted_bytes];
  }

  return Result(Status::kOk, frame.size());
}

size_t GCMFrameDecryptor::GetMaxPlaintextByteSize(
    cricket::MediaType media_type,
    size_t encrypted_frame_size) {
 return encrypted_frame_size;
}

void gen_params(byte key[KEY_SIZE], byte iv[BLOCK_SIZE])
{
    int rc = RAND_bytes(key, KEY_SIZE);
    if (rc != 1)
       RTC_LOG(LS_VERBOSE) << "XXX RAND_bytes key failed";

    rc = RAND_bytes(iv, BLOCK_SIZE);
    if (rc != 1)
      RTC_LOG(LS_VERBOSE) << "XXX RAND_bytes for iv failed";
}

void aes_encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ptext, secure_string& ctext)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
    if (rc != 1)
      RTC_LOG(LS_VERBOSE) << "XXX EVP_EncryptInit_ex failed";

    // Recovered text expands upto BLOCK_SIZE
    ctext.resize(ptext.size()+BLOCK_SIZE);
    int out_len1 = (int)ctext.size();

    rc = EVP_EncryptUpdate(ctx.get(), (byte*)&ctext[0], &out_len1, (const byte*)&ptext[0], (int)ptext.size());
    if (rc != 1)
      RTC_LOG(LS_VERBOSE) << "XXX EVP_EncryptUpdate failed";
  
    int out_len2 = (int)ctext.size() - out_len1;
    rc = EVP_EncryptFinal_ex(ctx.get(), (byte*)&ctext[0]+out_len1, &out_len2);
    if (rc != 1)
      RTC_LOG(LS_VERBOSE) << "XXX EVP_EncryptFinal_ex failed";

    // Set cipher text size now that we know it
    ctext.resize(out_len1 + out_len2);
}

void aes_decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ctext, secure_string& rtext)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
    if (rc != 1)
      RTC_LOG(LS_VERBOSE) << "XXX EVP_DecryptInit_ex failed";

    // Recovered text contracts upto BLOCK_SIZE
    rtext.resize(ctext.size());
    int out_len1 = (int)rtext.size();

    rc = EVP_DecryptUpdate(ctx.get(), (byte*)&rtext[0], &out_len1, (const byte*)&ctext[0], (int)ctext.size());
    if (rc != 1)
      RTC_LOG(LS_VERBOSE) << "XXX EVP_DecryptUpdate failed";
  
    int out_len2 = (int)rtext.size() - out_len1;
    rc = EVP_DecryptFinal_ex(ctx.get(), (byte*)&rtext[0]+out_len1, &out_len2);
    if (rc != 1)
      RTC_LOG(LS_VERBOSE) << "XXX EVP_DecryptFinal_ex failed";

    // Set recovered text size now that we know it
    rtext.resize(out_len1 + out_len2);
}

}