package br.com.zapia.wpp.api.ws.model.communication;

public class CheckIdIsOnWhatsAppResponse {

    private int status;
    private String jid;
    private boolean biz;

    public int getStatus() {
        return status;
    }

    public String getJid() {
        return jid;
    }

    public boolean isBiz() {
        return biz;
    }
}
