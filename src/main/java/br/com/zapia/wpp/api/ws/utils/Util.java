package br.com.zapia.wpp.api.ws.utils;

import br.com.zapia.wpp.api.ws.Constants;
import br.com.zapia.wpp.api.ws.binary.protos.WebMessageInfo;
import br.com.zapia.wpp.api.ws.model.*;
import com.google.common.hash.Hashing;
import com.google.common.primitives.Bytes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;
import org.apache.tika.Tika;
import org.bytedeco.ffmpeg.global.avutil;
import org.bytedeco.javacv.FFmpegFrameGrabber;
import org.bytedeco.javacv.Java2DFrameConverter;
import org.opencv.core.MatOfByte;
import org.opencv.core.MatOfInt;
import org.opencv.imgcodecs.Imgcodecs;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.InflaterOutputStream;

public class Util {

    private static final Logger logger = Logger.getLogger(Util.class.getName());
    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

    public static final Curve25519 CURVE_25519 = Curve25519.getInstance(Curve25519.BEST);

    public static final Gson GSON = new GsonBuilder().create();

    public static SignedKeyPair signedKeyPair(Curve25519KeyPair keyPair, int keyId) {
        var signKeys = CURVE_25519.generateKeyPair();
        var pubKey = new byte[33];
        pubKey[0] = 5;
        System.arraycopy(keyPair.getPublicKey(), 0, pubKey, 1, keyPair.getPublicKey().length);

        var signature = CURVE_25519.calculateSignature(keyPair.getPrivateKey(), pubKey);

        return new SignedKeyPair(signKeys, signature, keyId);
    }

    public static byte[] getRandomBytes(int length) throws NoSuchAlgorithmException {
        byte[] bytes = new byte[length];
        SecureRandom.getInstanceStrong().nextBytes(bytes);
        return bytes;
    }

    public static byte[] hkdfExpand(byte[] bytes, int length, byte[] info) {
        var staticSalt32Byte = new byte[]{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

        return hkdfExpand(bytes, length, staticSalt32Byte, info);
    }

    public static byte[] hkdfExpand(byte[] bytes, int length, byte[] salt, byte[] info) {
        var hkdf = HKDF.fromHmacSha256();

        return hkdf.extractAndExpand(salt, bytes, info, length);
    }

    public static byte[] encryptWa(byte[] encKey, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        byte[] iv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        SecretKeySpec secretKey = new SecretKeySpec(encKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return Bytes.concat(iv, cipher.update(data), cipher.doFinal());
    }

    public static byte[] decryptWa(byte[] encKey, byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKey = new SecretKeySpec(encKey, "AES");
        byte[] iv = Arrays.copyOf(data, 16);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return Bytes.concat(cipher.update(Arrays.copyOfRange(data, 16, data.length)), cipher.doFinal());
    }

    public static EncryptedStream encryptStream(byte[] stream, MessageType messageType) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var mediaKey = getRandomBytes(32);
        var generatedMediaKey = getMediaKey(mediaKey, messageType);


        SecretKeySpec secretKey = new SecretKeySpec(generatedMediaKey.getCipherKey(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(generatedMediaKey.getIv()));


        var encStream = cipher.doFinal(stream);

        var hmac = Arrays.copyOf(Hashing.hmacSha256(generatedMediaKey.getMacKey())
                .newHasher()
                .putBytes(Bytes.concat(generatedMediaKey.getIv(), encStream))
                .hash().asBytes(), 10);

        var sha256Plain = Hashing.sha256()
                .newHasher()
                .putBytes(stream)
                .hash().asBytes();

        var sha256Enc = Hashing.sha256()
                .newHasher()
                .putBytes(Bytes.concat(encStream, hmac))
                .hash().asBytes();

        return new EncryptedStream(mediaKey, Bytes.concat(encStream, hmac), hmac, sha256Enc, sha256Plain, stream.length);
    }

    public static byte[] decryptStream(byte[] stream, byte[] mediaKey, MessageType messageType) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var generatedMediaKey = getMediaKey(mediaKey, messageType);


        SecretKeySpec secretKey = new SecretKeySpec(generatedMediaKey.getCipherKey(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(generatedMediaKey.getIv()));

        var fileData = Arrays.copyOf(stream, stream.length - 10);
        var hmacValidation = Arrays.copyOfRange(stream, stream.length - 10, stream.length);
        var hmac = Arrays.copyOf(Hashing.hmacSha256(generatedMediaKey.getMacKey())
                .newHasher()
                .putBytes(Bytes.concat(generatedMediaKey.getIv(), fileData))
                .hash().asBytes(), 10);

        if (!Arrays.equals(hmacValidation, hmac))
            throw new IllegalStateException("HMAC validation failed on decrypt stream");

        return cipher.doFinal(fileData);
    }

    public static File convertByteArrayToFile(byte[] data, String fileName) throws IOException {
        var tempFile = File.createTempFile(fileName, ".tmp");
        Files.write(tempFile.toPath(), data);
        return tempFile;
    }

    public static MediaKey getMediaKey(byte[] mediaKey, MessageType messageType) {
        var expandedMediaKey = hkdfExpand(mediaKey, 112, Constants.HKDFInfoKeys.get(messageType).getBytes(StandardCharsets.UTF_8));
        return new MediaKey(Arrays.copyOf(expandedMediaKey, 16), Arrays.copyOfRange(expandedMediaKey, 16, 48), Arrays.copyOfRange(expandedMediaKey, 48, 80));
    }

    public static String bytesToHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    public static String convertJidToSend(String jid) {
        return jid.replace("@c.us", "@s.whatsapp.net");
    }

    public static String convertJidReceived(String jid) {
        return jid.replace("@s.whatsapp.net", "@c.us");
    }

    public static JsonObject groupActionsByType(JsonArray jsonArray) {
        var jsonObject = new JsonObject();

        for (int i = 0; i < jsonArray.size(); i++) {
            var current = jsonArray.get(i).getAsJsonArray();
            switch (current.get(0).getAsString()) {
                case "message":
                case "groups_v2":
                case "notification":
                case "call_log":
                case "security":
                    getOrAddJsonArrayToJsonObject("msg", jsonObject).add(current);
                    break;
                default:
                    logger.log(Level.WARNING, "Received unknown action type: {" + current.get(0).getAsString() + "} with content: {" + current + "}");
            }
        }

        return jsonObject;
    }

    public static JsonArray getOrAddJsonArrayToJsonObject(String key, JsonObject jsonObject) {
        if (!jsonObject.has(key) || !jsonObject.get(key).isJsonArray())
            jsonObject.add(key, new JsonArray());

        return jsonObject.getAsJsonArray(key);
    }

    public static String encodeFile(File file) throws IOException {
        byte[] data = Files.readAllBytes(file.toPath());
        return Base64.getEncoder().encodeToString(data);
    }

    public static String encodeURIComponent(String data) {
        return URLEncoder.encode(data, StandardCharsets.UTF_8)
                .replace("+", "%20")
                .replace("%21", "!")
                .replace("%27", "'")
                .replace("%28", "(")
                .replace("%29", ")")
                .replace("%7E", "~");
    }

    public static String detectMimeType(byte[] data) {
        var mime = new Tika().detect(data);
        if (mime.equals("application/ogg")) {
            mime = "audio/ogg; codecs=opus";
        }
        return mime;
    }

    public static byte[] generateThumbnail(byte[] streamFile, MessageType messageType) throws IOException, InterruptedException {
        switch (messageType) {
            case IMAGE, STICKER -> {
                return scaleImage(streamFile, 48, 48);
            }
            case VIDEO -> {
                return scaleImage(extractFirstFrameFromVideo(streamFile), 48, 48);
            }
            default -> {
                return new byte[0];
            }
        }
    }

    public static byte[] scaleImage(byte[] fileData, int width, int height) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(fileData);
        BufferedImage img = ImageIO.read(in);
        if (height == 0) {
            height = (width * img.getHeight()) / img.getWidth();
        }
        if (width == 0) {
            width = (height * img.getWidth()) / img.getHeight();
        }
        Image scaledImage = img.getScaledInstance(width, height, Image.SCALE_SMOOTH);
        BufferedImage imageBuff = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        imageBuff.getGraphics().drawImage(scaledImage, 0, 0, new Color(0, 0, 0), null);

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        ImageIO.write(imageBuff, "jpg", buffer);

        return buffer.toByteArray();
    }

    public static byte[] extractFirstFrameFromVideo(byte[] videoData) throws IOException {
        avutil.av_log_set_level(avutil.AV_LOG_ERROR);
        var baos = new ByteArrayOutputStream();
        var bufferedImage = new BufferedImage(48, 48, BufferedImage.TYPE_INT_RGB);
        var frameGrabber = new FFmpegFrameGrabber(new ByteArrayInputStream(videoData));
        frameGrabber.start();
        Java2DFrameConverter.copy(frameGrabber.grab(), bufferedImage);
        ImageIO.write(bufferedImage, "jpeg", baos);
        frameGrabber.stop();
        return baos.toByteArray();
    }

    public static int getMediaDuration(byte[] streamFile) throws IOException {
        avutil.av_log_set_level(avutil.AV_LOG_ERROR);
        var frameGrabber = new FFmpegFrameGrabber(new ByteArrayInputStream(streamFile));
        frameGrabber.start();
        return (int) (frameGrabber.getLengthInTime() / 1000000);
    }

    public static byte[] convertImageToWebp(byte[] imgData) {
        nu.pattern.OpenCV.loadLocally();
        var image = Imgcodecs.imdecode(new MatOfByte(imgData), Imgcodecs.IMREAD_UNCHANGED);
        var parameters = new MatOfInt(Imgcodecs.IMWRITE_WEBP_QUALITY, 100);
        var output = new MatOfByte();
        Imgcodecs.imencode(".webp", image, output, parameters);
        return output.toArray();
    }

    public static Dimension getImageDimension(byte[] imgData) throws IOException {
        ImageInputStream iis = ImageIO.createImageInputStream(new ByteArrayInputStream(imgData));
        Iterator<ImageReader> readers = ImageIO.getImageReaders(iis);
        while (readers.hasNext()) {
            ImageReader reader = readers.next();
            try {
                reader.setInput(iis);
                int width = reader.getWidth(reader.getMinIndex());
                int height = reader.getHeight(reader.getMinIndex());
                return new Dimension(width, height);
            } catch (IOException ignore) {
                iis.reset();
            } finally {
                iis.close();
                reader.dispose();
            }
        }

        throw new IOException("Not a known image file");
    }

    public static boolean isStringNullOrEmpty(String value) {
        return value == null || value.isEmpty();
    }

    public static String emptyStringOrValue(String value) {
        if (value == null)
            return "";
        return value;
    }

    public static boolean isJsonArrayByteArray(JsonArray jsonArray) {
        try {
            Util.GSON.fromJson(jsonArray, byte[].class);
            return true;
        } catch (Exception ignore) {
            return false;
        }
    }

    public static boolean isGroupJid(String jid) {
        return jid.endsWith("@g.us");
    }

    public static WebMessageInfo convertMessageCollectionItemToWebMessageInfo(MessageCollectionItem messageCollectionItem) throws InvalidProtocolBufferException {
        var msgBuilder = WebMessageInfo.newBuilder();
        JsonFormat.parser().ignoringUnknownFields().merge(Util.GSON.toJson(messageCollectionItem.getJsonObject()), msgBuilder);
        return msgBuilder.build();
    }

    public static boolean isNewMessage(LocalDateTime connectTime, MessageCollectionItem messageCollectionItem) {
        return connectTime.isBefore(messageCollectionItem.getTimeStamp());
    }

    public static byte[] inflateBytes(byte[] data) throws IOException {
        var out = new ByteArrayOutputStream();
        var inflater = new InflaterOutputStream(out);
        inflater.write(data, 0, data.length);
        return out.toByteArray();
    }
}
