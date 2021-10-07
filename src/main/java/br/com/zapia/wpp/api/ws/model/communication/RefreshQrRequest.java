package br.com.zapia.wpp.api.ws.model.communication;

import br.com.zapia.wpp.api.ws.utils.JsonUtil;

public class RefreshQrRequest {

    public String toJson(){
        var dataInit = new Object[]{
                "admin",
                "Conn",
                "reref"
        };
        return JsonUtil.I.getGson().toJson(dataInit);
    }

}
