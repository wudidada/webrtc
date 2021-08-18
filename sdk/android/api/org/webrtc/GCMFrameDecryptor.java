package org.webrtc;

public class GCMFrameDecryptor implements FrameDecryptor {
    @Override
    public long getNativeFrameDecryptor() {
        return nativeGetGCMFrameDecryptor();
    }

    private static native long nativeGetGCMFrameDecryptor();
}
