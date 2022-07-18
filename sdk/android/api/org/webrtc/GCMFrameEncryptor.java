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

    public setKey(int[] key) {
    }

    private static native long nativeGetGCMFrameEncryptor();

    private static native void nativeSetKey();
}
