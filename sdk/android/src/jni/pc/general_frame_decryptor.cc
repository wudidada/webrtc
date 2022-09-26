#include "sdk/android/src/jni/pc/general_frame_decryptor.h"

#include "sdk/android/generated_peerconnection_jni/GeneralFrameDecryptor_jni.h"
#include "sdk/android/src/jni/jni_helpers.h"
#include "sdk/android/native_api/jni/java_types.h"

#include <stddef.h>
#include <stdio.h>
#include <jni.h>

#include <vector>

namespace webrtc {
namespace jni {
GeneralFrameDecryptor::GeneralFrameDecryptor(JNIEnv* env) {
  jclass encryAndDecryClassTemp = env->FindClass("org/pjsip/pjsua2/service/EncryAndDecry");
  encryAndDecryClass = env->NewGlobalRef(encryAndDecryClassTemp);
}

GeneralFrameDecryptor::~GeneralFrameDecryptor() {
  encryAndDecryClass = env->NewGlobalRef(encryAndDecryClassTemp);
}

GeneralFrameDecryptor::Result GeneralFrameDecryptor::Decrypt(
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
      unencrypted_bytes = 10;
      break;
    case cricket::MEDIA_TYPE_DATA:
      break;
    case cricket::MEDIA_TYPE_UNSUPPORTED:
      break;
  }

  // write unencrypted frame head
  for (size_t i = 0; i < unencrypted_bytes; i++) {
    frame[i] = encrypted_frame[i];
  }

  JNIEnv* env = AttachCurrentThreadIfNeeded();

  // type convert: native to Java
  rtc::ArrayView<const uint8_t> encrypted_frame_payload = encrypted_frame.subview(unencrypted_bytes);
    jbyteArray jarrayIn, jarrayOut;
  jarrayIn = env->NewByteArray(encrypted_frame_payload.size()));
  env->SetByteArrayRegion(jarrayIn, 0, encrypted_frame_payload.size(), reinterpret_cast<const jbyte*>(encrypted_frame_payload.data()));

  // call Java side function
  decryMethod = env->GetStaticMethodID(encryAndDecryClass, "decryByte", "([B)[B");
  jarrayOut = env->CallStaticObjectMethod(encryAndDecryClass, decryMethod, jarrayIn);

  // type convert: Java to native
  int8_t* frame_payload = reinterpret_cast<int8_t*>(env->GetByteArrayElements(jarrayOut, 0));

  // write encrypted frame data
  size_t j_length = env.GetArrayLength(jarrayOut);
  for (size_t i = 0; i < j_length; ++i) {
    frame[i+unencrypted_bytes] = frame_payload[i];
  }

  return Result(Status::kOk, unencrypted_bytes + j_length);
}

size_t GeneralFrameDecryptor::GetMaxPlaintextByteSize(cricket::MediaType media_type,
                                                      size_t encrypted_frame_size) {
  return encrypted_frame_size;
}

static jlong JNI_GeneralFrameDecryptor_GetGeneralFrameDecryptor(JNIEnv* jni) {
  return jlongFromPointer(new GeneralFrameDecryptor(jni));
}
}  // namespace jni
}  // namespace webrtc