package org.webrtc;

public class GeneralFrameEncryptor implements FrameEncryptor {
    private static final String TAG = "GeneralFrameEncryptor";

    private final long nativeEncryptor;

    public GeneralFrameEncryptor() {
        nativeEncryptor = nativeGetGeneralFrameEncryptor();
    }

    @CalledByNative
    public static void encrypt() {
        Logging.d(TAG, "encrypting!!!");
    }

    // TODO glue GetMaxCiphertextByteSize
//    @CalledByNative
//    public int GetMaxCiphertextByteSize(MidiaType media_type, int frame_size)

    @Override
    public long getNativeFrameEncryptor() {
        return nativeGetGeneralFrameEncryptor();
    }

    private static native long nativeGetGeneralFrameEncryptor();
}
