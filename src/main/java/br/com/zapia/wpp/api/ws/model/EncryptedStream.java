package br.com.zapia.wpp.api.ws.model;

public class EncryptedStream {

    private final byte[] mediaKey;
    private final byte[] encryptedStream;
    private final byte[] hmac;
    private final byte[] sha256Enc;
    private final byte[] sha256Plain;
    private final int fileLength;

    public EncryptedStream(byte[] mediaKey, byte[] encryptedStream, byte[] hmac, byte[] sha256Enc, byte[] sha256Plain, int fileLength) {
        this.mediaKey = mediaKey;
        this.encryptedStream = encryptedStream;
        this.hmac = hmac;
        this.sha256Enc = sha256Enc;
        this.sha256Plain = sha256Plain;
        this.fileLength = fileLength;
    }

    public byte[] getMediaKey() {
        return mediaKey;
    }

    public byte[] getEncryptedStream() {
        return encryptedStream;
    }

    public byte[] getHmac() {
        return hmac;
    }

    public byte[] getSha256Enc() {
        return sha256Enc;
    }

    public byte[] getSha256Plain() {
        return sha256Plain;
    }

    public int getFileLength() {
        return fileLength;
    }
}
