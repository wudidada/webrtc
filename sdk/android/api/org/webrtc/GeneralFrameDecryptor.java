package org.webrtc;

public class GeneralFrameDecryptor implements FrameDecryptor {
    private static final String TAG = "GeneralFrameDecryptor";

    private final long nativeDecryptor;

    public GeneralFrameDecryptor() {
        nativeDecryptor = nativeGetGeneralFrameDecryptor();
    }

    @CalledByNative
    public static void decrypt() {
        Logging.d(TAG, "encrypting!!!");
    }

    // TODO glue GetMaxPlaintextByteSize
//    @CalledByNative
//    public int getMaxCiphertextByteSize(MidiaType media_type, int encrypted_frame_size)

    @Override
    public long getNativeFrameDecryptor() {
        return nativeDecryptor;
    }

    private static native long nativeGetGeneralFrameDecryptor();
}
