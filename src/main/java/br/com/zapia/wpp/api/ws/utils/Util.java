package br.com.zapia.wpp.api.ws.utils;

import com.google.common.primitives.Bytes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Util {

    private static final Logger logger = Logger.getLogger(Util.class.getName());
    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

    public static final Gson GSON = new GsonBuilder().create();

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

}
