package org.webrtc;

public class GCMFrameEncryptor implements FrameEncryptor{
    @Override
    public long getNativeFrameEncryptor() {
        return nativeGetGCMFrameEncryptor();
    }

    private static native long nativeGetGCMFrameEncryptor();
}
