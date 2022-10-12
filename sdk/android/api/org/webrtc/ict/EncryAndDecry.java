package org.webrtc.ict;

import org.webrtc.CalledByNative;

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
