package org.webrtc;

public class GeneralFrameEncryptor implements FrameEncryptor {
    private static final String TAG = "GeneralFrameEncryptor";

    private final long nativeEncryptor;

    public GeneralFrameEncryptor() {
        nativeEncryptor = nativeGetGeneralFrameEncryptor();
    }

//    @CalledByNative
    public byte[] encrypt(byte[] frame) {
        Logging.d(TAG, "encrypting!!!");
        byte[] encrpytedFrame = new byte[frame.length];
        for (int i = 0; i < frame.length; i++) {
            encrpytedFrame[i] = (byte) ~frame[i];
        }
        return encrpytedFrame;
    }

    // TODO glue GetMaxCiphertextByteSize
//    @CalledByNative
//    public int GetMaxCiphertextByteSize(MidiaType media_type, int frame_size)

    @Override
    public long getNativeFrameEncryptor() {
        return nativeGetGeneralFrameEncryptor();
    }

    private static native long nativeGetGeneralFrameEncryptor();
}
