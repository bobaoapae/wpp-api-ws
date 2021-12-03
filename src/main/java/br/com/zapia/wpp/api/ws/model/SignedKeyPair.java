package br.com.zapia.wpp.api.ws.model;

import org.whispersystems.curve25519.Curve25519KeyPair;

public class SignedKeyPair {

    private final Curve25519KeyPair keyPair;
    private final byte[] signature;
    private final int keyId;

    public SignedKeyPair(Curve25519KeyPair keyPair, byte[] signature, int keyId) {
        this.keyPair = keyPair;
        this.signature = signature;
        this.keyId = keyId;
    }

    public Curve25519KeyPair getKeyPair() {
        return keyPair;
    }

    public byte[] getSignature() {
        return signature;
    }

    public int getKeyId() {
        return keyId;
    }
}
