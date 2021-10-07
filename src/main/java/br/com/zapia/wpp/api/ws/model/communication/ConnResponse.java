package br.com.zapia.wpp.api.ws.model.communication;

public class ConnResponse {

    private int battery;
    private int binVersion;
    private String browserToken;
    private String clientToken;
    private boolean connected;
    private String platform;
    private String pushname;
    private String ref;
    private String secret;
    private String serverToken;
    private String wid;

    public int getBattery() {
        return battery;
    }

    public int getBinVersion() {
        return binVersion;
    }

    public String getBrowserToken() {
        return browserToken;
    }

    public String getClientToken() {
        return clientToken;
    }

    public boolean isConnected() {
        return connected;
    }

    public String getPushname() {
        return pushname;
    }

    public String getRef() {
        return ref;
    }

    public String getServerToken() {
        return serverToken;
    }

    public String getWid() {
        return wid;
    }

    public String getSecret() {
        return secret;
    }

    public String getPlatform() {
        return platform;
    }
}
