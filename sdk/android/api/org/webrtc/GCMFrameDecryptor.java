package org.webrtc;

public class GCMFrameDecryptor implements FrameDecryptor {

    private final int[] list;

    public GCMFrameDecryptor(int[] list) {
        this.list = list;
    }

    @Override
    public long getNativeFrameDecryptor() {
        return nativeGetGCMFrameDecryptor(list);
    }

    private static native long nativeGetGCMFrameDecryptor(int[] myList);
}
