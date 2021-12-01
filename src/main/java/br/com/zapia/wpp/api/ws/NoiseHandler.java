package br.com.zapia.wpp.api.ws;

import br.com.zapia.wpp.api.ws.binary.BinaryBuffer;
import br.com.zapia.wpp.api.ws.binary.WhatsAppBinaryBuffer;
import org.whispersystems.curve25519.Curve25519KeyPair;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.function.Consumer;

public class NoiseHandler {

    private final Curve25519KeyPair keyPair;
    private final WhatsAppBinaryBuffer inBinary;
    private byte[] encKey;
    private int writeCounter;
    private boolean sentIntro;
    private boolean isFinished;

    public NoiseHandler(Curve25519KeyPair keyPair) {
        this.keyPair = keyPair;
        inBinary = new WhatsAppBinaryBuffer();
    }

    public synchronized byte[] encodeFrame(byte[] data) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        if (isFinished)
            data = encrypt(data);

        var intro = new byte[0];
        if (!sentIntro) {
            sentIntro = true;
            intro = Constants.NOISE_WA_HEADER;
        }

        return new BinaryBuffer()
                .writeBytes(intro)
                .writeUInt8(data.length >> 16)
                .writeUInt16(65535 & data.length)
                .writeBytes(data)
                .readWrittenBytes();
    }

    public synchronized void decodeFrame(byte[] data, Consumer<byte[]> onFrame) {
        inBinary.writeBytes(data);
        while (inBinary.canPeek()) {
            inBinary.resetPosition();
            var bytesLength = getBytesSize();
            var bytes = inBinary.readBytes(bytesLength);
            if (isFinished) {
                //TODO: decrypt and unpack
            }

            onFrame.accept(bytes);
        }
    }

    public synchronized byte[] encrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var tagLength = 128 >> 3;

        var cipher = Cipher.getInstance("AES/GCM/NoPadding");

        var keySpec = new SecretKeySpec(encKey, "AES");

        var gcmParameterSpec = new GCMParameterSpec(tagLength, generateIV(writeCounter));

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

        return cipher.doFinal(data);
    }

    private int getBytesSize() {
        return (inBinary.readUInt8() << 16) | inBinary.readUInt16();
    }

    public synchronized byte[] generateIV(int writeCounter) {
        return ByteBuffer.allocate(12)
                .putLong(4, writeCounter)
                .array();
    }
}
