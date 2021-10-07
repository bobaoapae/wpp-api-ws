package br.com.zapia.wpp.api.ws.model.communication;

public class InitResponse {

    private int status;
    private long time;
    private int ttl;
    private boolean update;
    private String ref;
    private String curr;

    public int getStatus() {
        return status;
    }

    public long getTime() {
        return time;
    }

    public int getTtl() {
        return ttl;
    }

    public boolean isUpdate() {
        return update;
    }

    public String getRef() {
        return ref;
    }

    public String getCurr() {
        return curr;
    }
}
