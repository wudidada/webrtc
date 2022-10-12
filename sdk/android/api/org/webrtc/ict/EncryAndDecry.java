package org.webrtc.ict;

public class EncryAndDecry {

    @CalledByNative
    public static byte[] encryByte(byte[] data) {
        return data;
    }

    @CalledByNative
    public static byte[] decryByte(byte[] data) {
        return data;
    }
}
