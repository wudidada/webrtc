package org.webrtc;

public class GeneralFrameDecryptor implements FrameDecryptor {
    private static final String TAG = "GeneralFrameDecryptor";

    private final long nativeDecryptor;

    public GeneralFrameDecryptor() {
        nativeDecryptor = nativeGetGeneralFrameDecryptor();
    }

    public static interface Observer {

    }


//        @CalledByNative
    public byte[] decrypt(byte[] encrpytedFrame) {
        Logging.d(TAG, "encrypting!!!");
        byte[] frame = new byte[encrpytedFrame.length];
        for (int i = 0; i < encrpytedFrame.length; i++) {
            frame[i] = (byte) ~encrpytedFrame[i];
        }
        return frame;
    }
    // TODO glue GetMaxPlaintextByteSize
//    @CalledByNative
//    public int getMaxCiphertextByteSize(MidiaType media_type, int encrypted_frame_size)

    @Override
    public long getNativeFrameDecryptor() {
        return nativeDecryptor;
    }

    private static native long nativeGetGeneralFrameDecryptor();
}
