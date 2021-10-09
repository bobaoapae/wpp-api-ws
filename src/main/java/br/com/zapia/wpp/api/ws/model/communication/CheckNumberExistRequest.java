package br.com.zapia.wpp.api.ws.model.communication;

import br.com.zapia.wpp.api.ws.utils.Util;

public class CheckNumberExistRequest implements IWARequest {

    private final String number;

    public CheckNumberExistRequest(String number) {
        this.number = number;
    }

    @Override
    public String toJson() {
        var data = new Object[]{
                "query",
                "exist",
                number + "@s.whatsapp.net"
        };
        return Util.GSON.toJson(data);
    }
}
