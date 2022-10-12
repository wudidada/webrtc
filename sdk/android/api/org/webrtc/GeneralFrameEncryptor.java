package org.webrtc;

public class GeneralFrameEncryptor implements FrameEncryptor {
    
    private final long nativeEncryptor;

    public GeneralFrameEncryptor() {
        nativeEncryptor = nativeGetGeneralFrameEncryptor();
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
