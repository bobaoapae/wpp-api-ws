package br.com.zapia.wpp.api.ws.model.communication;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class NodeWhatsAppFrame implements IWhatsAppFrame {

    private final JsonArray node;

    public NodeWhatsAppFrame(JsonArray node) {
        this.node = node;
    }

    public JsonArray getNode() {
        return node;
    }

    public String getTag() {
        return getNode().get(0).getAsString();
    }

    public JsonObject getAttrs() {
        return getNode().get(1).getAsJsonObject();
    }

    public JsonArray getData() {
        if (getNode().get(2) != null && getNode().get(2).isJsonArray()) {
            return getNode().get(2).getAsJsonArray();
        }

        return new JsonArray();
    }
}
