package br.com.zapia.wpp.api.ws.utils;

import com.google.common.primitives.Bytes;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class EncryptionUtil {

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

}
