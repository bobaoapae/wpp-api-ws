package br.com.zapia.wpp.api.ws.model;

public class CommunicationKeys {

    private final byte[] sharedKey;
    private final byte[] expandedKey;
    private final byte[] encryptedKeys;
    private final byte[] decryptedKeys;
    private final byte[] encKey;
    private final byte[] macKey;

    public CommunicationKeys(byte[] sharedKey, byte[] expandedKey, byte[] encryptedKeys, byte[] decryptedKeys, byte[] encKey, byte[] macKey) {
        this.sharedKey = sharedKey;
        this.expandedKey = expandedKey;
        this.encryptedKeys = encryptedKeys;
        this.decryptedKeys = decryptedKeys;
        this.encKey = encKey;
        this.macKey = macKey;
    }

    public byte[] getSharedKey() {
        return sharedKey;
    }

    public byte[] getExpandedKey() {
        return expandedKey;
    }

    public byte[] getEncryptedKeys() {
        return encryptedKeys;
    }

    public byte[] getDecryptedKeys() {
        return decryptedKeys;
    }

    public byte[] getEncKey() {
        return encKey;
    }

    public byte[] getMacKey() {
        return macKey;
    }
}
