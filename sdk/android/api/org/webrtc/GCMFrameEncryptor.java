package org.webrtc;

public class GCMFrameEncryptor implements FrameEncryptor {

    private final long nativeEncryptor;

    public GCMFrameEncryptor() {
        nativeEncryptor = nativeGetGCMFrameEncryptor();
    }

    @Override
    public long getNativeFrameEncryptor() {
        return nativeGetGCMFrameEncryptor();
    }

    public void setKey(int[] key) {
        nativeSetKey(key);
    }

    private static native long nativeGetGCMFrameEncryptor();

    private native void nativeSetKey(int[] key);
}
