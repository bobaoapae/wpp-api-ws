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
        if (getNode().size() < 1 || getNode().get(0) == null || getNode().get(0).isJsonNull())
            return "";

        return getNode().get(0).getAsString();
    }

    public JsonObject getAttrs() {
        if (getNode().size() < 2 || getNode().get(1) == null || getNode().get(1).isJsonNull())
            return new JsonObject();

        return getNode().get(1).getAsJsonObject();
    }

    public JsonArray getData() {
        if (getNode().size() < 3 || getNode().get(2) == null || !getNode().get(2).isJsonArray())
            return new JsonArray();

        return getNode().get(2).getAsJsonArray();

    }
}
