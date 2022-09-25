package org.webrtc;

public class SimpleFrameEncryptor implements FrameEncryptor {

    private final long nativeEncryptor;

    public SimpleFrameEncryptor() {
        nativeEncryptor = nativeGetSimpleFrameEncryptor();
    }

    @CalledByNative
    public byte[] encrypt(byte[] encryptedFrame) {
        return encryptedFrame;
    }

    // TODO glue GetMaxCiphertextByteSize
//    @CalledByNative
//    public int GetMaxCiphertextByteSize(MidiaType media_type, int frame_size)

    @Override
    public long getNativeFrameEncryptor() {
        return nativeGetSimpleFrameEncryptor();
    }

    private static native long nativeGetSimpleFrameEncryptor();
}
