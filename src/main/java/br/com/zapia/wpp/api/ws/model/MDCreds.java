package br.com.zapia.wpp.api.ws.model;

import org.whispersystems.curve25519.Curve25519KeyPair;

public class MDCreds {

    private MeInfo meInfo;
    private final Curve25519KeyPair noiseKey;
    private final Curve25519KeyPair signedIdentityKey;
    private final SignedKeyPair signedPreKey;
    private final int registrationId;
    private final String advSecretKey;
    private final int nextPreKeyId;
    private final int firstUnuploadedPreKeyId;
    private final boolean serverHasPreKeys;

    public MDCreds(Curve25519KeyPair noiseKey, Curve25519KeyPair signedIdentityKey, SignedKeyPair signedPreKey, int registrationId, String advSecretKey, int nextPreKeyId, int firstUnuploadedPreKeyId, boolean serverHasPreKeys) {
        this.noiseKey = noiseKey;
        this.signedIdentityKey = signedIdentityKey;
        this.signedPreKey = signedPreKey;
        this.registrationId = registrationId;
        this.advSecretKey = advSecretKey;
        this.nextPreKeyId = nextPreKeyId;
        this.firstUnuploadedPreKeyId = firstUnuploadedPreKeyId;
        this.serverHasPreKeys = serverHasPreKeys;
    }

    public MeInfo getMeInfo() {
        return meInfo;
    }

    public void setMeInfo(MeInfo meInfo) {
        this.meInfo = meInfo;
    }

    public Curve25519KeyPair getNoiseKey() {
        return noiseKey;
    }

    public Curve25519KeyPair getSignedIdentityKey() {
        return signedIdentityKey;
    }

    public SignedKeyPair getSignedPreKey() {
        return signedPreKey;
    }

    public int getRegistrationId() {
        return registrationId;
    }

    public String getAdvSecretKey() {
        return advSecretKey;
    }

    public int getNextPreKeyId() {
        return nextPreKeyId;
    }

    public int getFirstUnuploadedPreKeyId() {
        return firstUnuploadedPreKeyId;
    }

    public boolean isServerHasPreKeys() {
        return serverHasPreKeys;
    }
}
