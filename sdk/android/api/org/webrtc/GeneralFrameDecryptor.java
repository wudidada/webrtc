package org.webrtc;

public class GeneralFrameDecryptor implements FrameDecryptor {

    private final long nativeDecryptor;

    public GeneralFrameDecryptor() {
        nativeDecryptor = nativeGetGeneralFrameDecryptor();
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
