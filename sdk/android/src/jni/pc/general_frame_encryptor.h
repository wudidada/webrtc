#ifndef SDK_ANDROID_SRC_JNI_PC_GENERAL_FRAME_ENCRYPTOR_H_
#define SDK_ANDROID_SRC_JNI_PC_GENERAL_FRAME_ENCRYPTOR_H_

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "api/array_view.h"
#include "api/crypto/frame_encryptor_interface.h"
#include "api/media_types.h"
#include "rtc_base/ref_counted_object.h"
#include "sdk/android/src/jni/jni_helpers.h"

#include <jni.h>


std::atomic<jclass> g_GeneralFrameEncryptor_clazz(nullptr);
#ifndef GeneralFrameEncryptor_clazz_defined
#define GeneralFrameEncryptor_clazz_defined
inline jclass GeneralFrameEncryptor_clazz(JNIEnv* env) {
  return LazyGetClass(env, "org/webrtc/GeneralFrameEncryptor",
                                     &g_GeneralFrameEncryptor_clazz);
}
#endif

static std::atomic<jmethodID> g_GeneralFrameEncryptor_encryByte(nullptr);

namespace webrtc {
namespace jni {
class GeneralFrameEncryptor
    : public rtc::RefCountedObject<FrameEncryptorInterface> {
 public:
  int Encrypt(cricket::MediaType media_type,
              uint32_t ssrc,
              rtc::ArrayView<const uint8_t> additional_data,
              rtc::ArrayView<const uint8_t> frame,
              rtc::ArrayView<uint8_t> encrypted_frame,
              size_t* bytes_written) override;

  size_t GetMaxCiphertextByteSize(cricket::MediaType media_type,
                                  size_t frame_size) override;
};
}  // namespace jni
}  // namespace webrtc

#endif  // SDK_ANDROID_SRC_JNI_PC_GENERAL_FRAME_ENCRYPTOR_H_