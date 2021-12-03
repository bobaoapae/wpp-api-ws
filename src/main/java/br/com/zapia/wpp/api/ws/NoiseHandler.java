package br.com.zapia.wpp.api.ws;

import br.com.zapia.wpp.api.ws.binary.BinaryArray;
import br.com.zapia.wpp.api.ws.binary.BinaryBuffer;
import br.com.zapia.wpp.api.ws.binary.BinaryMessage;
import br.com.zapia.wpp.api.ws.binary.WABinaryDecoder;
import br.com.zapia.wpp.api.ws.binary.protos.Details;
import br.com.zapia.wpp.api.ws.binary.protos.HandshakeMessage;
import br.com.zapia.wpp.api.ws.binary.protos.NoiseCertificate;
import br.com.zapia.wpp.api.ws.model.communication.BinaryWhatsAppFrame;
import br.com.zapia.wpp.api.ws.model.communication.IWhatsAppFrame;
import br.com.zapia.wpp.api.ws.model.communication.NodeWhatsAppFrame;
import br.com.zapia.wpp.api.ws.utils.Util;
import com.google.common.hash.Hashing;
import com.google.protobuf.InvalidProtocolBufferException;
import org.whispersystems.curve25519.Curve25519KeyPair;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class NoiseHandler {

    private final Curve25519KeyPair keyPair;
    private byte[] hash;
    private byte[] decKey;
    private byte[] encKey;
    private byte[] salt;
    private int writeCounter;
    private int readCounter;
    private boolean sentIntro;
    private boolean isFinished;

    public NoiseHandler(Curve25519KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public void init() {
        hash = BinaryArray.of(Constants.NOISE_MODE).data();
        decKey = hash;
        encKey = hash;
        salt = hash;

        authenticate(Constants.NOISE_WA_HEADER);
        authenticate(keyPair.getPublicKey());
    }

    public byte[][] localHKDF(byte[] data) {
        var key = Util.hkdfExpand(data, 64, salt, null);
        return new byte[][]{Arrays.copyOf(key, 32), Arrays.copyOfRange(key, 32, key.length)};
    }

    public void mixIntoKey(byte[] data) {
        var result = localHKDF(data);
        salt = result[0];
        encKey = result[1];
        decKey = result[1];
        readCounter = 0;
        writeCounter = 0;
    }

    public byte[] processHandshake(HandshakeMessage handshakeMessage, Curve25519KeyPair noiseKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidProtocolBufferException {
        authenticate(handshakeMessage.getServerHello().getEphemeral().toByteArray());
        var sharedKeyEphemeral = Util.CURVE_25519.calculateAgreement(handshakeMessage.getServerHello().getEphemeral().toByteArray(), keyPair.getPrivateKey());
        mixIntoKey(sharedKeyEphemeral);

        var decStaticContent = decrypt(handshakeMessage.getServerHello().getStatic().toByteArray());
        var sharedStaticContent = Util.CURVE_25519.calculateAgreement(decStaticContent, keyPair.getPrivateKey());
        mixIntoKey(sharedStaticContent);

        var certDecoded = decrypt(handshakeMessage.getServerHello().getPayload().toByteArray());

        var noiseCertificate = NoiseCertificate.parseFrom(certDecoded);
        var certDetails = Details.parseFrom(noiseCertificate.getDetails());

        if (!Arrays.equals(decStaticContent, certDetails.getKey().toByteArray())) {
            throw new RuntimeException("Certification match failed");
        }

        var keyEnc = encrypt(noiseKey.getPublicKey());
        var sharedPrivateNoiseKey = Util.CURVE_25519.calculateAgreement(handshakeMessage.getServerHello().getEphemeral().toByteArray(), noiseKey.getPrivateKey());
        mixIntoKey(sharedPrivateNoiseKey);

        return keyEnc;
    }

    public byte[] encodeFrame(byte[] data) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
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

    public IWhatsAppFrame decodeFrame(byte[] data) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
        var message = new BinaryMessage(data);

        if (message.getLength() == 8913411) {
            throw new IllegalStateException("Invalid message received");
        }

        if (isFinished) {
            var bytes = BinaryBuffer.fromBytes(decrypt(message.getDecoded().data()));
            if ((bytes.readUInt8() & 2) != 0) {
                bytes = BinaryBuffer.fromBytes(Util.inflateBytes(bytes.remaining().readAllBytes()));
            }
            return new NodeWhatsAppFrame(new WABinaryDecoder(bytes.remaining().readAllBytes(), true).read());
        } else {
            return new BinaryWhatsAppFrame(message.getDecoded().data());
        }
        /*inBinary.writeBytes(data);
        while (inBinary.canPeek()) {
            inBinary.resetPosition();
            var bytesLength = getBytesSize();
            var bytes = inBinary.readBytes(bytesLength);
            inBinary.markPosition();
            if (isFinished) {
                bytes = decrypt(bytes);
                bytes = Util.inflateBytes(bytes);
                onFrame.accept(new NodeWhatsAppFrame(new WABinaryDecoder(bytes).read()));
            } else {
                onFrame.accept(new BinaryWhatsAppFrame(bytes));
            }
        }*/
    }

    public void authenticate(byte[] data) {
        if (!isFinished) {
            hash = Hashing.sha256().newHasher().putBytes(hash).putBytes(data).hash().asBytes();
        }
    }

    public byte[] encrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");

        var keySpec = new SecretKeySpec(encKey, "AES");

        var gcmParameterSpec = new GCMParameterSpec(128, generateIV(writeCounter++));

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        cipher.updateAAD(hash);

        var result = cipher.doFinal(data);
        authenticate(result);

        return result;
    }

    public byte[] decrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");

        var keySpec = new SecretKeySpec(decKey, "AES");

        var gcmParameterSpec = new GCMParameterSpec(128, generateIV(isFinished ? readCounter++ : writeCounter++));

        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        cipher.updateAAD(hash);

        authenticate(data);

        return cipher.doFinal(data);
    }

    public byte[] generateIV(int writeCounter) {
        return ByteBuffer.allocate(12)
                .putLong(4, writeCounter)
                .array();
    }

    public void finishInit() {
        var result = localHKDF(new byte[0]);
        encKey = result[0];
        decKey = result[1];
        hash = new byte[0];
        readCounter = 0;
        writeCounter = 0;
        isFinished = true;
    }
}
