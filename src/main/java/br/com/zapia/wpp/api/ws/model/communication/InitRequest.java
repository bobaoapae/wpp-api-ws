package br.com.zapia.wpp.api.ws.model.communication;

import br.com.zapia.wpp.api.ws.Constants;
import br.com.zapia.wpp.api.ws.utils.Util;

public class InitRequest implements IWARequest {

    private final String clientId;

    public InitRequest(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public String toJson() {
        var dataInit = new Object[]{
                "admin",
                "init",
                Constants.WS_VERSION,
                Constants.WS_BROWSER_DESC,
                clientId,
                true
        };
        return Util.GSON.toJson(dataInit);
    }
}
