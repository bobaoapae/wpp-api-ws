package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import com.google.gson.JsonObject;

public class QuickReplyCollectionItem extends BaseCollectionItem<QuickReplyCollectionItem> {

    private String shortcut;
    private String message;

    public QuickReplyCollectionItem(WhatsAppClient whatsAppClient, JsonObject jsonObject) {
        super(whatsAppClient, jsonObject);
    }

    public String getShortcut() {
        return shortcut;
    }

    public String getMessage() {
        return message;
    }

    @Override
    void build() {
        shortcut = jsonObject.get("short").getAsString();
        message = jsonObject.get("message").getAsString();
        id = shortcut;
    }

    @Override
    protected void update(QuickReplyCollectionItem baseCollectionItem) {

    }

    @Override
    protected void update(JsonObject jsonObject) {

    }
}
