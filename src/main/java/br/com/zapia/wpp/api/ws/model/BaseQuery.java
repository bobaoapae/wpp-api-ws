package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.utils.JsonUtil;

public class BaseQuery {

    private final String type;
    private final String epoch;

    public BaseQuery(String type, String epoch) {
        this.type = type;
        this.epoch = epoch;
    }

    public String toJson() {
        var dataInit = new Object[]{
                "query",
                JsonUtil.I.getGson().toJson(this)
        };
        return JsonUtil.I.getGson().toJson(dataInit);
    }
}
