package br.com.zapia.wpp.api.ws.model;

public class MediaKey {

    private final byte[] iv;
    private final byte[] cipherKey;
    private final byte[] macKey;

    public MediaKey(byte[] iv, byte[] cipherKey, byte[] macKey) {
        this.iv = iv;
        this.cipherKey = cipherKey;
        this.macKey = macKey;
    }

    public byte[] getIv() {
        return iv;
    }

    public byte[] getCipherKey() {
        return cipherKey;
    }

    public byte[] getMacKey() {
        return macKey;
    }
}
