package br.com.zapia.wpp.api.ws.model.communication;

import br.com.zapia.wpp.api.ws.utils.Util;

public record CheckIdIsOnWhatsApp(String jid) implements IWARequest {

    public CheckIdIsOnWhatsApp(String jid) {
        this.jid = Util.convertJidToSend(jid);
    }

    @Override
    public String toJson() {
        var data = new Object[]{
                "query",
                "exist",
                jid
        };
        return Util.GSON.toJson(data);
    }
}
