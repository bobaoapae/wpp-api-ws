package br.com.zapia.wpp.api.ws.model.communication;

import com.google.gson.JsonArray;

public class NodeWhatsAppFrame implements IWhatsAppFrame {

    private final JsonArray node;

    public NodeWhatsAppFrame(JsonArray node) {
        this.node = node;
    }

    public JsonArray getNode() {
        return node;
    }
}
