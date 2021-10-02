package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.Constants;
import br.com.zapia.wpp.api.ws.utils.JsonUtil;

public class InitRequest {

    private final String clientId;

    public InitRequest(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public String toString() {
        var dataInit = new Object[]{
                "admin",
                "init",
                Constants.WS_VERSION,
                Constants.WS_BROWSER_DESC,
                clientId,
                true
        };
        return JsonUtil.I.getGson().toJson(dataInit);
    }
}
