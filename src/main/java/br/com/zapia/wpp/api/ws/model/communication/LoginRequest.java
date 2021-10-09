package br.com.zapia.wpp.api.ws.model.communication;

import br.com.zapia.wpp.api.ws.model.AuthInfo;
import br.com.zapia.wpp.api.ws.utils.Util;

public class LoginRequest implements IWARequest {

    private final AuthInfo authInfo;

    public LoginRequest(AuthInfo authInfo) {
        this.authInfo = authInfo;
    }

    @Override
    public String toJson() {
        var dataInit = new Object[]{
                "admin",
                "login",
                authInfo.getClientToken(),
                authInfo.getServerToken(),
                authInfo.getClientId(),
                "takeover"
        };
        return Util.GSON.toJson(dataInit);
    }

}
