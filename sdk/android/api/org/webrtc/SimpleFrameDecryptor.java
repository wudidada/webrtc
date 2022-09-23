package org.webrtc;

public class SimpleFrameDecryptor implements FrameDecryptor {

    private final long nativeDecryptor;

    public SimpleFrameDecryptor() {
        nativeDecryptor = nativeGetSimpleFrameDecryptor();
    }

    @Override
    public long getNativeFrameDecryptor() {
        return nativeDecryptor;
    }

    public void setKey(int[] key) {
        nativeSetKey(key);
    }

    private static native long nativeGetSimpleFrameDecryptor();

    private native void nativeSetKey(int[] key);
}
