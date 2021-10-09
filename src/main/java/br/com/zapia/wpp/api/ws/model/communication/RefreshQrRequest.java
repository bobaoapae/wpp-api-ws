package br.com.zapia.wpp.api.ws.model.communication;

import br.com.zapia.wpp.api.ws.utils.Util;

public class RefreshQrRequest implements IWARequest {

    @Override
    public String toJson() {
        var data = new Object[]{
                "admin",
                "Conn",
                "reref"
        };
        return Util.GSON.toJson(data);
    }

}
