package org.webrtc;

public class SimpleFrameEncryptor implements FrameEncryptor {

    private final long nativeEncryptor;

    public SimpleFrameEncryptor() {
        nativeEncryptor = nativeGetSimpleFrameEncryptor();
    }

    @Override
    public long getNativeFrameEncryptor() {
        return nativeGetSimpleFrameEncryptor();
    }

    public void setKey(int[] key) {
        nativeSetKey(key);
    }

    private static native long nativeGetSimpleFrameEncryptor();

    private native void nativeSetKey(int[] key);
}
