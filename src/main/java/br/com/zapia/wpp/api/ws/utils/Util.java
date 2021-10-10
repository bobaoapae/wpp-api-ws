package br.com.zapia.wpp.api.ws.utils;

import at.favre.lib.crypto.HKDF;
import br.com.zapia.wpp.api.ws.Constants;
import br.com.zapia.wpp.api.ws.model.EncryptedStream;
import br.com.zapia.wpp.api.ws.model.MediaKey;
import br.com.zapia.wpp.api.ws.model.MessageType;
import com.google.common.hash.Hashing;
import com.google.common.primitives.Bytes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.humble.video.*;
import io.humble.video.awt.MediaPictureConverter;
import io.humble.video.awt.MediaPictureConverterFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Util {

    private static final Logger logger = Logger.getLogger(Util.class.getName());
    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

    public static final Gson GSON = new GsonBuilder().create();

    public static byte[] getRandomBytes(int length) throws NoSuchAlgorithmException {
        byte[] bytes = new byte[length];
        SecureRandom.getInstanceStrong().nextBytes(bytes);
        return bytes;
    }

    public static byte[] hkdfExpand(byte[] bytes, int length, byte[] info) {
        var hkdf = HKDF.fromHmacSha256();

        var staticSalt32Byte = new byte[]{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

        return hkdf.extractAndExpand(staticSalt32Byte, bytes, info, length);
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

    public static byte[] generateThumbnail(byte[] streamFile, MessageType messageType) throws IOException, InterruptedException {
        switch (messageType) {
            case IMAGE -> {
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

    public static byte[] extractFirstFrameFromVideo(byte[] videoData) throws IOException, InterruptedException {
        var baos = new ByteArrayOutputStream();
        var fileTemp = File.createTempFile("extractFrame", ".tmp");
        Files.write(fileTemp.toPath(), videoData);
        var demuxer = Demuxer.make();
        demuxer.open(fileTemp.getAbsolutePath(), null, false, true, null, null);

        int numStreams = demuxer.getNumStreams();

        /*
         * Iterate through the streams to find the first video stream
         */
        int videoStreamId = -1;
        long streamStartTime = Global.NO_PTS;
        Decoder videoDecoder = null;
        for (int i = 0; i < numStreams; i++) {
            final DemuxerStream stream = demuxer.getStream(i);
            streamStartTime = stream.getStartTime();
            final Decoder decoder = stream.getDecoder();
            if (decoder != null && decoder.getCodecType() == MediaDescriptor.Type.MEDIA_VIDEO) {
                videoStreamId = i;
                videoDecoder = decoder;
                // stop at the first one.
                break;
            }
        }
        if (videoStreamId == -1)
            throw new IOException("could not find video stream in container");

        /*
         * Now we have found the audio stream in this file.  Let's open up our decoder so it can
         * do work.
         */
        videoDecoder.open(null, null);

        final MediaPicture picture = MediaPicture.make(
                videoDecoder.getWidth(),
                videoDecoder.getHeight(),
                videoDecoder.getPixelFormat());

        /** A converter object we'll use to convert the picture in the video to a BGR_24 format that Java Swing
         * can work with. You can still access the data directly in the MediaPicture if you prefer, but this
         * abstracts away from this demo most of that byte-conversion work. Go read the source code for the
         * converters if you're a glutton for punishment.
         */
        final MediaPictureConverter converter =
                MediaPictureConverterFactory.createConverter(
                        MediaPictureConverterFactory.HUMBLE_BGR_24,
                        picture);
        BufferedImage image = null;

        final MediaPacket packet = MediaPacket.make();
        while (demuxer.read(packet) >= 0) {
            /**
             * Now we have a packet, let's see if it belongs to our video stream
             */
            if (packet.getStreamIndex() == videoStreamId) {
                /**
                 * A packet can actually contain multiple sets of samples (or frames of samples
                 * in decoding speak).  So, we may need to call decode  multiple
                 * times at different offsets in the packet's data.  We capture that here.
                 */
                int offset = 0;
                int bytesRead = 0;
                do {
                    bytesRead += videoDecoder.decode(picture, packet, offset);
                    if (picture.isComplete()) {
                        image = converter.toImage(image, picture);
                        ImageIO.write(image, "jpeg", baos);
                        break;
                    }
                    offset += bytesRead;
                } while (offset < packet.getSize());
            }
        }

        do {
            videoDecoder.decode(picture, null, 0);
        } while (picture.isComplete());
        fileTemp.delete();

        return baos.toByteArray();
    }

    public static int getMediaDuration(byte[] streamFile) throws IOException, InterruptedException {
        var fileTemp = File.createTempFile("extractFrame", ".tmp");
        Files.write(fileTemp.toPath(), streamFile);
        var demuxer = Demuxer.make();
        demuxer.open(fileTemp.getAbsolutePath(), null, false, true, null, null);
        var duration = demuxer.getDuration();
        if (duration == Global.NO_PTS) {
            return 0;
        }
        double d = 1.0 * duration / Global.DEFAULT_PTS_PER_SECOND;

        demuxer.close();
        fileTemp.delete();

        return (int) d;
    }
}
