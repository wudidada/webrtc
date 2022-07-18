#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "api/array_view.h"
#include "api/crypto/frame_encryptor_interface.h"
#include "api/media_types.h"
#include "rtc_base/ref_counted_object.h"

namespace webrtc {

class GCMFrameEncryptor
    : public rtc::RefCountedObject<FrameEncryptorInterface> {
 public:
  explicit GCMFrameEncryptor();
  int Encrypt(unsigned char* key,
              unsigned char* plaintext,
              size_t plaintext_len,
              unsigned char* iv,
              unsigned char* aad,
              int aad_len,
              size_t& ciphertext_len) override;

  size_t GetMaxCiphertextByteSize(cricket::MediaType media_type,
                                  size_t frame_size) override;
  void SetKey(std::vector<uint8_t> key_bytes);

 private:
  std::vector<uint8_t> key_bytes;
};
}  // namespace webrtc