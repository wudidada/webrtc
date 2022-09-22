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
    }

    private static native long nativeGetGCMFrameDecryptor();
}
