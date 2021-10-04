package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.Constants;
import br.com.zapia.wpp.api.ws.utils.JsonUtil;

public class LoginRequest {

    private final AuthInfo authInfo;

    public LoginRequest(AuthInfo authInfo) {
        this.authInfo = authInfo;
    }

    public String toJson(){
        var dataInit = new Object[]{
                "admin",
                "login",
                authInfo.getClientToken(),
                authInfo.getServerToken(),
                authInfo.getClientId(),
                "takeover"
        };
        return JsonUtil.I.getGson().toJson(dataInit);
    }

}
