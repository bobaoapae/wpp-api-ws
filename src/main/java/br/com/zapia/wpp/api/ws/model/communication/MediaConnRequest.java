package br.com.zapia.wpp.api.ws.model.communication;

import br.com.zapia.wpp.api.ws.utils.Util;

public class MediaConnRequest implements IWARequest {
    @Override
    public String toJson() {
        var data = new Object[]{
                "query",
                "mediaConn"
        };
        return Util.GSON.toJson(data);
    }
}
