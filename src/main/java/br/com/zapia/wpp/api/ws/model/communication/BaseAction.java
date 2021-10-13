package br.com.zapia.wpp.api.ws.model.communication;

import br.com.zapia.wpp.api.ws.utils.Util;
import com.google.gson.JsonArray;

public class BaseAction {

    private final String type;
    private final String epoch;
    private transient final JsonArray child;

    public BaseAction(String type, String epoch, JsonArray child) {
        this.type = type;
        this.epoch = epoch;
        this.child = child;
    }

    public final JsonArray toJsonArray() {
        var jsonObj = Util.GSON.toJsonTree(this).getAsJsonObject();
        var jsonArray = new JsonArray();
        jsonArray.add("action");
        jsonArray.add(jsonObj);
        jsonArray.add(child);
        return jsonArray;
    }
}
