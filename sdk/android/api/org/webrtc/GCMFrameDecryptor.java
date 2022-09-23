package org.webrtc;

public class GCMFrameDecryptor implements FrameDecryptor {

    private final long nativeDecryptor;

    public GCMFrameDecryptor() {
        nativeDecryptor = nativeGetGCMFrameDecryptor();
    }

    @Override
    public long getNativeFrameDecryptor() {
        return nativeDecryptor;
    }

    public void setKey(int[] key) {
        nativeSetKey(key);
    }

    private static native long nativeGetGCMFrameDecryptor();

    private native void nativeSetKey(int[] key);
}
