package br.com.zapia.wpp.api.ws.model.communication;

import br.com.zapia.wpp.api.ws.utils.JsonUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class BaseQuery {

    private final String type;
    private final String epoch;
    private final JsonArray child;

    public BaseQuery(String type, String epoch, JsonArray child) {
        this.type = type;
        this.epoch = epoch;
        this.child = child;
    }

    public JsonArray toJsonArray() {
        var jsonObj = new JsonObject();
        jsonObj.addProperty("type", type);
        jsonObj.addProperty("epoch", epoch);

        var jsonArray = new JsonArray();
        jsonArray.add("query");
        jsonArray.add(jsonObj);
        jsonArray.add(child);

        return jsonArray;
    }
}
